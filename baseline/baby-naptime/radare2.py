import subprocess
import tempfile
import os
import json
from typing import List, Dict, Union, Optional, Literal

class R2:
    def __init__(self, timeout: int = 60):
        """
        初始化radare2执行器
        :param timeout: 命令执行超时时间（秒）
        """
        self.timeout = timeout
        self._verify_r2()

    def _verify_r2(self):
        """验证radare2安装"""
        try:
            subprocess.run(['r2', '-qv'], check=True, 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE)
        except (FileNotFoundError, subprocess.CalledProcessError):
            raise RuntimeError("radare2未安装或版本过低，需要v5.8.0+")

    def _create_script(self, commands: List[str], output_format: str) -> str:
        """
        生成r2批处理脚本
        :param commands: 要执行的r2命令列表
        :param output_format: 输出格式要求（json/text）
        """
        script = [
            "e scr.color=0",
            "e bin.demangle=true"
        ]

        # 自动添加输出格式控制
        if output_format == 'json':
            script.append("e cmd.json=true")
        elif output_format == 'text':
            script.append("e cmd.json=false")

        script += commands
        return '\n'.join(script)

    def execute(self, 
               file_path: str,
               commands: str,
               output_format: Literal['raw', 'json', 'text'] = 'raw',
               input_args: Optional[List[str]] = None) -> Union[str, dict]:
        """
        执行radare2命令并返回结构化结果
        :param file_path: 目标文件路径
        :param commands: 要执行的r2命令（字符串或列表）
        :param output_format: 返回格式要求
            - raw: 原始输出
            - json: 自动解析JSON
            - text: 清理后的文本
        :param input_args: 传递给程序的命令行参数
        """
        # 参数标准化
        commands = "aaa;"+commands
        cmd_list = [commands] if isinstance(commands, str) else commands
        script = self._create_script(cmd_list, output_format)
        
        with tempfile.NamedTemporaryFile('w', delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            # 构建执行命令
            base_cmd = ['r2', '-e', 'bin.cache=true', '-q']
            if input_args:
                base_cmd += ['-d', '--']  # 调试模式允许传递参数
            else:
                base_cmd += []  # 无执行模式
            
            full_cmd = base_cmd + ['-i', script_path, file_path]
            if input_args:
                full_cmd += input_args

            result = subprocess.run(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=True
            )

            # 处理输出
            raw_output = result.stdout.decode('utf-8', errors='ignore')
            if commands == "aaa;aaa":
                raw_output = "success execute aaa"
            

            if output_format == 'json':
                return self._parse_json_output(raw_output)
            elif output_format == 'text':
                return self._clean_text_output(raw_output)
            
            return raw_output

        except subprocess.CalledProcessError as e:
            error_msg = f"命令执行失败: {e.stderr.decode()}"
            raise RuntimeError(error_msg)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"分析超时（{self.timeout}秒）")
        finally:
            os.remove(script_path)

    def _parse_json_output(self, raw: str) -> dict:
        """智能解析混合JSON输出"""
        json_objects = []
        decoder = json.JSONDecoder()
        
        buffer = raw.strip()
        while buffer:
            try:
                obj, idx = decoder.raw_decode(buffer)
                json_objects.append(obj)
                buffer = buffer[idx:].lstrip()
            except json.JSONDecodeError:
                break
                
        if not json_objects:
            raise ValueError("未找到有效JSON数据")
            
        # 合并多个JSON对象
        if len(json_objects) == 1:
            return json_objects[0]
        return {'results': json_objects}

    def _clean_text_output(self, raw: str) -> str:
        """清理文本输出"""
        lines = []
        for line in raw.split('\n'):
            # 过滤r2日志信息
            if line.startswith(('[0x', 'Cannot find', 'WARNING')):
                continue
            lines.append(line.strip())
        return '\n'.join(filter(None, lines))


''' 

# 使用示例
if __name__ == "__main__":
    r2 = R2(timeout=60)

   

    # 示例2：反汇编函数（文本）
    disasm = r2.execute(
        "code/vuln_server",
        commands="aaa",
        output_format='text'
    )
    print(disasm)  # 输出前500字符



    # 示例3：动态分析（带参数）
    try:
        dynamic = r2.execute(
            "./code/vuln_server",
            commands=["ood", "dc", "dr"],
            input_args=["test_input"],
            output_format='raw'
        )
        print("\n=== 寄存器状态 ===")
        print(dynamic)
    except Exception as e:
        print(f"动态分析失败: {str(e)}")
''' 