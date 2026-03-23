import sys
import time
import shlex
import os
from typing import Optional, List, Dict, Any
from pygdbmi.gdbcontroller import GdbController
from logger_config import logger
from redis_utils import RedisUtils


Record = Dict[str, Any]

class GdbMiClient:
    def __init__(self, exe_path: str, gdb_path: str = "gdb"):
        self.ctrl = GdbController(
            command=[gdb_path, "--nx", "--quiet", "--interpreter=mi2"]
        )
        self._send(f"-file-exec-and-symbols {shlex.quote(exe_path)}")
        self.program_output = []

    def _send(self, cmd: str, read_response: bool = True) -> List[Record]:
        return self.ctrl.write(cmd, read_response=read_response)

    def _drain(self, timeout: float = 0.5) -> List[Record]:
        records = self.ctrl.get_gdb_response(timeout_sec=timeout, raise_error_on_timeout=False)
        for r in records or []:
            self._collect_output(r)
        return records

    def _find_stopped(self, records: List[Record]) -> Optional[Record]:
        for r in records or []:
            self._collect_output(r)
            if r.get("message") == "stopped":
                return r
        return None

    def _collect_output(self, record: Record):
        rtype = record.get("type")
        stream = record.get("stream")
        payload = record.get("payload")
        
        if not payload or not isinstance(payload, str):
            return
            
        if rtype == "console":
            self.program_output.append(payload)
        elif rtype == "target" or stream == "stdout":
            self.program_output.append(payload)
        elif rtype == "output":
            self.program_output.append(payload)

    def wait_until_stopped(self, timeout: float = 5.0, initial_records: Optional[List[Record]] = None) -> Record:
        r = self._find_stopped(initial_records or [])
        if r:
            return r
        deadline = time.time() + timeout
        while time.time() < deadline:
            records = self._drain(0.5)
            r = self._find_stopped(records)
            if r:
                return r
        raise TimeoutError("Timeout waiting for program to stop")

    def insert_breakpoint(self, spec: str) -> List[Record]:
        return self._send(f"-break-insert {spec}")

    def run(self, args: Optional[List[str]] = None) -> List[Record]:
        if args:
            argv = " ".join(shlex.quote(a) for a in args)
            self._send(f"-exec-arguments {argv}")
        return self._send("-exec-run")

    def continue_(self) -> List[Record]:
        return self._send("-exec-continue")

    def next(self) -> List[Record]:
        return self._send("-exec-next")

    def step(self) -> List[Record]:
        return self._send("-exec-step")

    def get_frames(self) -> List[Record]:
        return self._send("-stack-list-frames")

    def eval_expr(self, expr: str) -> List[Record]:
        return self._send(f"-data-evaluate-expression {expr}")

    def list_locals(self) -> List[Record]:
        return self._send("-stack-list-variables --all-values")

    def get_program_output(self) -> str:
        output = "".join(self.program_output)
        output = output.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')
        output = output.replace('\\"', '"').replace('\\\\', '\\')
        return output

    def quit(self):
        try:
            self._drain(0.5)
        except Exception:
            pass
        try:
            self._send("-gdb-exit", read_response=False)
        except Exception:
            pass
        finally:
            try:
                self.ctrl.exit()
            except Exception:
                pass


class Debugger:
    
    def __init__(self, gdb_path: str = "gdb"):
        self.gdb_path = gdb_path
    
    def run_to_breakpoint_at_line(
        self,
        exe_path: str,
        source_file: str,
        line_no: int,
        args: Optional[List[str]] = None,
        input_file: Optional[str] = None,
        timeout: float = 10.0,
        debug: bool = False,
    ) -> Dict[str, Any]:
        redis_util = RedisUtils()
        function_name = redis_util.get("FunctionName")
        
        gdb = GdbMiClient(exe_path, gdb_path=self.gdb_path)
        
        if debug:
            logger.info(f"Debugger: exe={exe_path}, target={source_file}:{line_no}, function={function_name}")

        try:
            gdb._send("-gdb-set breakpoint pending on")

            if debug:
                logger.info("Step 1: Setting breakpoint at main")
            br_main = gdb.insert_breakpoint("main")

            if debug:
                logger.info(f"Step 2: Running to main{' with input redirection' if input_file else ''}")
            
            if input_file:
                if args:
                    argv = " ".join(shlex.quote(a) for a in args)
                    gdb._send(f"-exec-arguments {argv}")
                run_cmd = f"run < {input_file}"
                run_recs = gdb._send(f'-interpreter-exec console "{self._mi_quote(run_cmd)}"')
            else:
                run_recs = gdb.run(args=args)

            try:
                stop_main = gdb.wait_until_stopped(timeout=timeout, initial_records=run_recs)
            except Exception as e:
                error_msg = f"Failed to stop at main within timeout: {str(e)}"
                if debug:
                    logger.warning(error_msg)
                return {
                    "success": False,
                    "hit_function": False,
                    "hit_line": False,
                    "stop_reason": "timeout_at_main",
                    "debug_info": "Failed to reach main breakpoint",
                    "program_output": gdb.get_program_output()
                }

            function_bkptno = None
            line_bkptno = None
            
            if function_name:
                if debug:
                    logger.info(f"Step 3a: Setting breakpoint at function {function_name}")
                
                func_recs = gdb.insert_breakpoint(function_name)
                
                if self._bkpt_is_pending(func_recs):
                    if debug:
                        logger.warning(f"Function breakpoint at {function_name} is pending")
                
                function_bkptno = self._extract_bkpt_no(func_recs)
            
            if debug:
                logger.info(f"Step 3{'b' if function_name else ''}: Setting breakpoint at {source_file}:{line_no}")
            
            loc = f"{source_file}:{int(line_no)}"
            line_recs = gdb.insert_breakpoint(loc)
            
            if self._bkpt_is_pending(line_recs):
                if debug:
                    logger.warning(f"Line breakpoint at {loc} is pending")
            
            line_bkptno = self._extract_bkpt_no(line_recs)

            if debug:
                logger.info("Step 4: Continuing execution and checking for breakpoint hits")
            
            hit_function = False
            hit_line = False
            stop_reason = "unknown"
            
            max_continues = 100  
            continue_count = 0
            
            while continue_count < max_continues:
                cont_recs = gdb.continue_()
                
                try:
                    stopped = gdb.wait_until_stopped(timeout=timeout, initial_records=cont_recs)
                except Exception as e:
                    if debug:
                        logger.warning(f"Failed to stop after continue within timeout: {str(e)}")
                    stop_reason = "timeout"
                    break

                sp = (stopped or {}).get("payload") or {}
                reason = sp.get("reason")
                stop_reason = reason or "unknown"
                
                if reason in ("exited-normally", "exited", "exited-signalled"):
                    if debug:
                        logger.info(f"Program exited (reason={reason})")
                    stop_reason = reason
                    break
                
                if reason == "breakpoint-hit":
                    hit_bkptno = sp.get("bkptno")
                    
                    if function_bkptno and self._stopped_is_bkptno(stopped, function_bkptno):
                        hit_function = True
                        if debug:
                            logger.info(f"Function breakpoint hit: {function_name}")
                    
                    if line_bkptno and self._stopped_is_bkptno(stopped, line_bkptno):
                        hit_line = True
                        if debug:
                            logger.info(f"Line breakpoint hit: {source_file}:{line_no}")
                    elif self._stopped_matches_location(stopped, source_file, int(line_no)):
                        hit_line = True
                        if debug:
                            logger.info(f"Line breakpoint hit (by location): {source_file}:{line_no}")
                    
                    if hit_function or hit_line:
                        if not function_name or (hit_function and hit_line):
                            break
                        if debug:
                            logger.info("One breakpoint hit, continuing to check for the other...")
                    else:
                        if debug:
                            logger.info(f"Hit different breakpoint (#{hit_bkptno}), continuing...")
                else:
                    if debug:
                        logger.info(f"Stopped with reason: {reason}")
                    break
                
                continue_count += 1
            
            if continue_count >= max_continues:
                if debug:
                    logger.warning(f"Reached maximum continue limit ({max_continues})")
                stop_reason = "max_continues_reached"

            success = hit_line
            debug_info_parts = []
            
            if function_name:
                debug_info_parts.append(f"Function '{function_name}': {'HIT' if hit_function else 'NOT HIT'}")
            debug_info_parts.append(f"Line '{source_file}:{line_no}': {'HIT' if hit_line else 'NOT HIT'}")
            
            debug_info = " | ".join(debug_info_parts)
            
            if debug:
                logger.info(f"Result: {debug_info} | Stop reason: {stop_reason}")

            return {
                "success": success,
                "hit_function": hit_function,
                "hit_line": hit_line,
                "stop_reason": stop_reason,
                "debug_info": debug_info,
                "program_output": gdb.get_program_output()[:200]
            }

        except Exception as e:
            error_msg = f"Exception occurred: {str(e)}"
            if debug:
                logger.error(error_msg, exc_info=True)
            return {
                "success": False,
                "hit_function": False,
                "hit_line": False,
                "stop_reason": "exception",
                "debug_info": f"Exception: {str(e)[:2000]}",
                "program_output": gdb.get_program_output()[:200]
            }
        finally:
            gdb.quit()

    @staticmethod
    def _mi_quote(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _extract_bkpt_no(records: List[Record]) -> Optional[str]:
        for r in records or []:
            if r.get("message") == "done":
                payload = r.get("payload") or {}
                bkpt = payload.get("bkpt")
                if isinstance(bkpt, dict) and "number" in bkpt:
                    return bkpt["number"]
                if isinstance(bkpt, list) and bkpt:
                    first = bkpt[0]
                    if isinstance(first, dict) and "number" in first:
                        return first["number"]
        return None

    @staticmethod
    def _extract_bkpt_info(records: List[Record]) -> Optional[Dict[str, Any]]:
        for r in records or []:
            if r.get("message") == "done":
                payload = r.get("payload") or {}
                bkpt = payload.get("bkpt")
                if isinstance(bkpt, list) and bkpt:
                    bkpt = bkpt[0]
                if isinstance(bkpt, dict):
                    return bkpt
        return None

    @staticmethod
    def _bkpt_is_pending(records: List[Record]) -> bool:
        info = Debugger._extract_bkpt_info(records)
        if not info:
            return False
        if "pending" in info:
            return True
        addr = info.get("addr")
        if isinstance(addr, str) and ("PENDING" in addr or addr == "0x0"):
            return True
        return False

    @staticmethod
    def _stopped_is_bkptno(stopped_record: Record, bkptno: str) -> bool:
        payload = (stopped_record or {}).get("payload") or {}
        if payload.get("reason") != "breakpoint-hit":
            return False
        hit = payload.get("bkptno")
        return str(hit) == str(bkptno)

    @staticmethod
    def _stopped_matches_location(stopped_record: Record, source_file: str, line_no: int) -> bool:
        payload = (stopped_record or {}).get("payload") or {}
        if payload.get("reason") != "breakpoint-hit":
            return False
        frame = payload.get("frame") or {}
        reported_line = frame.get("line")
        if reported_line is None:
            return False
        try:
            if int(reported_line) != int(line_no):
                return False
        except ValueError:
            return False

        want_abs = os.path.normcase(os.path.abspath(source_file))
        full = frame.get("fullname")
        fil = frame.get("file")

        if full:
            got_abs = os.path.normcase(os.path.abspath(full))
            if got_abs == want_abs:
                return True
            if os.path.basename(got_abs) == os.path.basename(want_abs):
                return True
        if fil:
            if os.path.basename(fil) == os.path.basename(want_abs):
                return True
        return False


def pretty_print_records(tag: str, records: List[Record]):
    if not records:
        print(f"[{tag}] <no records>")
        return
    print(f"[{tag}]")
    for r in records:
        msg = r.get("message")
        payload = r.get("payload")
        if msg or payload:
            print(f"  - message={msg} payload={payload}")
        else:
            stream = r.get("type")
            content = r.get("payload") or r.get("stream")
            print(f"  - {stream}: {content}")


def extract_bkpt_no(records: List[Record]) -> Optional[str]:
    return Debugger._extract_bkpt_no(records)


def run_to_breakpoint_at_line(
    exe_path: str,
    source_file: str,
    line_no: int,
    args: Optional[List[str]] = None,
    input_file: Optional[str] = None,
    gdb_path: str = "gdb",
    timeout: float = 10.0,
    debug: bool = True,
) -> Dict[str, Any]:
    debugger = Debugger(gdb_path)
    return debugger.run_to_breakpoint_at_line(
        exe_path=exe_path,
        source_file=source_file,
        line_no=line_no,
        args=args,
        input_file=input_file,
        timeout=timeout,
        debug=debug
    )


    
if __name__ == "__main__":
    redis_util = RedisUtils()
    redis_util.set("FunctionName", 're_subcompile_string')
    debugger = Debugger()
    
    result = debugger.run_to_breakpoint_at_line(
        exe_path="/home/xxx/spbaseline/sqlite/sqlite3",
        source_file='/home/xxx/spbaseline/sqlite/shell.c',
        line_no=7620,
        args=None,
        input_file="/home/xxx/IntOAgent_New/poc/sqlite/0/input.txt",
        debug=True
    )
    print(f"Success: {result['success']}")
    print(f"Debug info: {result['debug_info']}")
    print(f"Program output:\n{result['program_output']}")
    print(f"Output length: {len(result['program_output'])}")