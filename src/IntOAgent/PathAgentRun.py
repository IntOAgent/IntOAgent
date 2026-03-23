import _config
from Node import Node
from PathAgent import *
import pandas as pd
from tqdm import tqdm
import time
from pathlib import Path
from typing import Dict
from redis_utils import RedisUtils

redis_util = RedisUtils()

CONFIG_FILE = "_config.py"
cur_dir_path = Path(__file__).parent
def update_config(vid, startfunc):
    # Read all lines from config file
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    # Remove last two lines if they exist
    if len(lines) >= 4:
        lines = lines[:-4]
    
    # Add new id and startfunc
    lines.append(f"id = {int(vid)}\n")
    lines.append(f"startfunc = '{startfunc}'\n")
    lines.append(f"funcnamechainfile = 'extra/{_config.project_name}/{str(vid)}/funcname.txt'\n")
    lines.append(f"funcbodychainfile = 'extra/{_config.project_name}/{str(vid)}/funcbody.txt'")
    
    # Write back to config file
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

def get_before_result(file_path: str) -> Dict:
    ''' Get before result from the given file path '''
    if not os.path.exists(file_path):
        return {}
    
    result = dict()
    with open(file_path, "r", encoding='utf-8') as f:
        for line in f.readlines():
            if line == "\n" or line.strip() == '' or len(line.strip()) < 2:
                continue
            # 解析时增加testcase_token和poc_token字段
            parts = line.strip().split(",")
            if len(parts) >= 5:  # 如果有5个字段（增加了testcase_token和poc_token）
                id, status, token, time, testcase_token, poc_token = parts[:6]
                result[id.strip()] = {
                    "status": status.strip(),
                    "token": float(token.strip()),
                    "time": float(time.strip()),
                    "testcase_token": float(testcase_token.strip()),
                    "poc_token": float(poc_token.strip()),
                    "testcase_time": float(time.strip()),
                    "poc_time": float(time.strip())
                }
            else:  # 兼容旧格式
                id, status, token, time = parts[:4]
                result[id.strip()] = {
                    "status": status.strip(),
                    "token": float(token.strip()),
                    "time": float(time.strip()),
                    "testcase_token": 0.0,
                    "poc_token": 0.0,
                    "testcase_time": 0,
                    "poc_time": 0
                }
    return result

def append_result(result_file, vid, status, token, elapsed_time, testcase_token, poc_token, testcase_time, poc_time):
    ''' Append result to the given file path '''
    with open(result_file, "a", encoding="utf-8", newline="") as f:
        f.write(f"{vid},{status},{token},{elapsed_time},{testcase_token},{poc_token},{testcase_time},{poc_time}\n")

if __name__ == "__main__":
    pathagent = PathAgent(_config.project_path, _config.vul_path)
    df = pd.read_csv(_config.vul_path)
    total_rows = len(df)

    # Chunk size (number of rows processed at a time)
    chunk_size = 100

    outdir = os.path.join("output", _config.project_name)
    os.makedirs(outdir, exist_ok=True)

    # Get before result to skip
    result_file = cur_dir_path / "output" / f"{_config.project_name}" / "result.txt"
    result_file.touch(exist_ok=True)
    results = get_before_result(result_file)
    skip_ids = results.keys()

    # Collect global results
    all_tokencount = []
    all_timelist = []
    all_status = []

    for chunk_idx, chunk_start in enumerate(range(0, total_rows, chunk_size), start=1):
        chunk_end = min(chunk_start + chunk_size, total_rows)
        df_chunk = df.iloc[chunk_start:chunk_end]

        tokencount = []
        timelist = []
        status_chunk = []

        # Process each row in the current chunk
        for _, row in tqdm(df_chunk.iterrows(),
                           total=len(df_chunk),
                           desc=f"Processing rows {chunk_start+1}-{chunk_end}"):
            vid = str(row["ID"])
            Run_startfunc = row["Closest Function Name"]
            Sink_code = row["Vul code"]
            print(f"[INFO] Processing ID {vid} with function name {Run_startfunc} and sink code {Sink_code}")
            redis_util.set("FunctionName", Run_startfunc)
            redis_util.set("SinkCode", Sink_code.strip('```'))
            # Skip IDs in the skip list
            if vid in skip_ids:
                print(f"[INFO] Skipping ID {vid}")
                tokencount.append(0)
                timelist.append(0.0)
                status_chunk.append("Skipped")
                continue
            
            # Clean up previous extra/{project_name}/{vid} if exists
            if os.path.exists(f"extra/{_config.project_name}/{vid}"):
                shutil.rmtree(f"extra/{_config.project_name}/{vid}")

            # Update config and run PathAgent
            update_config(vid, Run_startfunc)
            importlib.reload(_config)
            redis_util.set("TokenCount", "0")
            redis_util.set("PathAgentToken", "0")
            redis_util.set("TestcaseToken", "0")
            redis_util.set("PocToken", "0")
            redis_util.set("TestcaseTime", "0")
            redis_util.set("PocTime", "0")
            start_time = time.time()
            resultrun, token_count = pathagent.run(Run_startfunc)
            elapsed_time = time.time() - start_time
            token_count = float(redis_util.get("PathAgentToken"))
            if token_count == 0:
                token_count = float(redis_util.get("TokenCount"))
            testcase_token = float(redis_util.get("TestcaseToken"))
            poc_token = float(redis_util.get("PocToken"))
            
            redis_util.set("PathAgentToken", "0")
            redis_util.set("TestcaseToken", "0")
            redis_util.set("PocToken", "0")
            
            print(testcase_token, poc_token)
            token_count += testcase_token + poc_token
            print(resultrun)
            tokencount.append(token_count)
            timelist.append(elapsed_time)

            # Default status is MayVulnerability (will be updated if PRUNE.txt is found)
            status_chunk.append("MayVulnerability")
            testcase_time = redis_util.get("TestcaseTime")
            poc_time = redis_util.get("PocTime")
            redis_util.set("TestcaseTime", "0")
            redis_util.set("PocTime", "0")
            if os.path.exists(f"extra/{_config.project_name}/{vid}/PRUNE.txt"):
                status_chunk[-1] = "FalsePositive"
                print(f"[INFO] {vid} is pruned!")
                append_result(result_file, vid, "FalsePositive", token_count, elapsed_time, testcase_token, poc_token, testcase_time, poc_time)
            else:
                append_result(result_file, vid, "MayVulnerability", token_count, elapsed_time, testcase_token, poc_token, testcase_time, poc_time)
            redis_util.set("TestcaseToken", "0")
            redis_util.set("PocToken", "0")
        # Find PRUNE.txt files
        # cmd = f"find extra/{_config.project_name} -type f -name PRUNE.txt"
        # result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        # prune_files = result.stdout.strip().split("\n") if result.stdout.strip() else []
        # prune_dirs = [os.path.basename(os.path.dirname(f)) for f in prune_files]

        # Update status for rows that match PRUNE.txt directories (except skipped rows)
        # for i, row in df_chunk.iterrows():
        #     if status_chunk[i - chunk_start] != "Skipped":
        #         if str(row["ID"]) in prune_dirs:
        #             status_chunk[i - chunk_start] = "FalsePositive"
                        
        # Append chunk results to global results
        all_tokencount.extend(tokencount)
        all_timelist.extend(timelist)
        all_status.extend(status_chunk)

        # Save partial results with row range in filename
        df_chunk = df_chunk.copy()
        df_chunk['Status'] = status_chunk
        df_chunk['Token'] = tokencount
        df_chunk['Time'] = timelist
        

        part_csv = os.path.join(
            outdir,
            f"{_config.type}_false_positive_part{chunk_idx}_rows{chunk_start+1}-{chunk_end}.csv"
        )

        for i, row in df_chunk.iterrows():
            vid = str(row["ID"])
            if vid in results:
                df_chunk.at[i, "Status"] = results[vid]["status"]
                df_chunk.at[i, "Token"] = results[vid]["token"]
                df_chunk.at[i, "Time"] = results[vid]["time"]
            
        df_chunk.to_csv(part_csv, index=False)

        print(f"[INFO] Saved partial result to: {part_csv}")
        print(f"[INFO] Finished rows {chunk_start+1}-{chunk_end}: "
              f"{status_chunk.count('FalsePositive')} FalsePositive, "
              f"{status_chunk.count('MayVulnerability')} MayVulnerability, "
              f"{status_chunk.count('Skipped')} Skipped")

    # Save final merged results
    df['Token'] = all_tokencount
    df['Time'] = all_timelist
    df['Status'] = all_status

    # 在保存最终结果前添加额外的列
    df['Testcase_Token'] = [0.0] * len(df)
    df['Poc_Token'] = [0.0] * len(df)
    results = get_before_result(result_file)

    for i, row in df.iterrows():
        vid = str(row["ID"])
        if vid in results:
            df.at[i, "Status"] = results[vid]["status"]
            df.at[i, "Token"] = results[vid]["token"]
            df.at[i, "Time"] = results[vid]["time"]
            df.at[i, "Testcase_Token"] = results[vid].get("testcase_token", 0.0)
            df.at[i, "Poc_Token"] = results[vid].get("poc_token", 0.0)
        
    out_csv = os.path.join(outdir, f"{_config.type}_false_positive.csv")
    df.to_csv(out_csv, index=False)
    targets = [os.path.join(d, _config.project_name) 
            for d in ["chat_history/PathAgent","extra","poc","pytemp","reports"] 
            if os.path.exists(os.path.join(d, _config.project_name))]
    zip_path = os.path.join(outdir, f"{_config.project_name}_pot_{_config.type}.zip")
    print(f"[INFO] Generated final CSV: {out_csv}")
    print(f"[INFO] Final stats: "
          f"{(df['Status'] == 'FalsePositive').sum()} FalsePositive, "
          f"{(df['Status'] == 'MayVulnerability').sum()} MayVulnerability, "
          f"{(df['Status'] == 'Skipped').sum()} Skipped")
    subprocess.run(["zip", "-r", zip_path] + targets, check=True) 
    print("[INFO] !!!PathAgent has done!!!")
    for p in targets:
        subprocess.run(f"rm -rf {p}/*", shell=True, check=True)




    #     vid_dir = os.path.join("extra", project_name, str(vid))
    #     if not os.path.exists(vid_dir):
    #         continue

    #     # Traverse subfolders under vid_dir
    #     for subfolder in os.listdir(vid_dir):
    #         subfolder_path = os.path.join(vid_dir, subfolder)
    #         if not os.path.isdir(subfolder_path):
    #             continue

    #         extra_path = os.path.join(subfolder_path, "extra.txt")
    #         if not os.path.exists(extra_path):
    #             continue

    #         # Run subprocess and capture + print output
    #         process = subprocess.Popen(
    #             [
    #                 "python3", "PocAgent.py",
    #                 "-p", project_path,
    #                 "-b", bin_path,
    #                 "-f", startfunc,
    #                 "-e", extra_path
    #             ],
    #             stdout=subprocess.PIPE,
    #             stderr=subprocess.STDOUT,
    #             text=True
    #         )
    #         for line in process.stdout:
    #             print(line, end="")  # print subprocess output in real time
    #         process.wait()

    #     # After running all subfolders, check poc/project_name/vid
    #     poc_vid_dir = os.path.join("poc", project_name, str(vid))
    #     vid_result = 0
    #     if os.path.exists(poc_vid_dir):
    #         for item in os.listdir(poc_vid_dir):
    #             item_path = os.path.join(poc_vid_dir, item)
    #             if os.path.isdir(item_path) and os.listdir(item_path):  # non-empty folder
    #                 vid_result = 1
    #                 break

    #     results.append({"ID": vid, "Project": project_name, "Result": vid_result, "Token": pathagent.llm.output_token()})
    #     pathagent.llm.clear_token()

    # # Save final results
    # final_csv_path = os.path.join("poc", project_name, "all_results.csv")
    # os.makedirs(os.path.dirname(final_csv_path), exist_ok=True)
    # pd.DataFrame(results).to_csv(final_csv_path, index=False)
    
    # print(f"All results saved to {final_csv_path}")