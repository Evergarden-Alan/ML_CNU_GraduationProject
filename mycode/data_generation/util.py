import os
import sys
import json

def preprocess_dns(file_path,output_path):
       logs = []
       # 打开文件，并逐行读取
       print("开始处理DNS日志")
       with open(file_path, "r", encoding="utf-8") as file:
              for line in file:
                     # 去掉每行末尾的换行符
                     line = line.strip()
                     parts = line.split(" ")
                     log_entry = {
                            "index": parts[0],                                   # 行号
                            "timestamp": parts[1] + " " + parts[2],              # 时间戳
                            "src_ip": parts[3],                                  # 源 IP
                            "dst_ip": parts[5],                                  # 目标 IP
                            "protocol": parts[6],                                # 协议类型
                            "length": parts[7],                                  # 数据包长度
                            "query_type": parts[8] + " " + parts[9],             # 查询类型
                            "domain_name": parts[10]                             # 域名
                            }
                     logs.append(log_entry)
       print("开始写入文件")
       # 将解析好的日志写入JSON文件
       with open(output_path, "w", encoding="utf-8") as json_file:
              json.dump(logs, json_file, ensure_ascii=False, indent=4)          
       print(f"DNS日志已成功写入 {output_path} 文件。")
       
       
       
def preprocess_webbrowser(file_path,output_path):
       logs = []

       # 打开并逐行读取文件
       print("开始处理浏览器日志文件")
       # 打开并逐行读取日志文件
       with open(file_path, "r", encoding="utf-8") as file:
              for line in file:
                     # 去掉行末的换行符
                     line = line.strip()

                     # 确保行不为空且符合格式
                     if " - " not in line:
                            continue  # 跳过不符合格式的行

                     # 拆分时间戳和日志内容
                     timestamp, log_content = line.split(" - ", 1)
                     
                     # 进一步拆分线程信息和日志信息
                     thread_info, log_info = log_content.split(": ", 1)

                     # 分析日志信息，提取不同的字段
                     log_parts = log_info.split(" ")
                     module, event = log_parts[0], log_parts[1]

                     # 提取参数，例如`this=10def580`, `stream=e1ee920`等
                     params = {}
                     for part in log_parts[2:]:
                            if '=' in part:
                                   key, value = part.split("=", 1)
                                   params[key] = value
                            
                     # 将解析后的日志信息添加到字典中
                     log_entry = {
                     "timestamp": timestamp,
                     "thread": thread_info.strip("[]"),
                     "module": module,
                     "event": event,
                     "params": params
                     }
                     
                     # 添加日志到列表中
                     logs.append(log_entry)
       # 将解析好的日志写入JSON文件
       with open(output_path, "w", encoding="utf-8") as json_file:
              json.dump(logs, json_file, ensure_ascii=False, indent=4)

       print(f"日志已成功写入 {output_path} 文件。")

def preprocess_windows(file_path,output_path):

       # 存储所有日志的列表
       logs = []

       print("开始处理Windows系统文件")
       # 打开并逐行读取日志文件
       with open(file_path, "r", encoding="utf-8") as file:
              current_log = {}  # 用于存储当前日志条目
              for line in file:
                     # 去掉行末的换行符
                     line = line.strip()

                     # 检查每一行内容的开头，判断日志项的类型并存储相应信息
                     if line.startswith("Audit Success"):
                            # 如果遇到新的"Audit Success"，先将之前的日志保存到列表中
                            if current_log:
                                   logs.append(current_log)
                            # 初始化一个新的日志条目
                            current_log = {
                                   "Event": "Audit Success",
                                   "Details": {}
                            }

                     elif "Event ID:" in line:
                            current_log["Event ID"] = line.split()[-1]

                     elif "Date:" in line:
                            current_log["Date"] = line.split(":", 1)[1].strip()

                     elif line.startswith("Subject"):
                            # 初始化"Subject"子项
                            current_log["Details"]["Subject"] = {}
                     elif "Security ID:" in line:
                            current_log["Details"]["Subject"]["Security ID"] = line.split(":", 1)[1].strip()
                     elif "Account Name:" in line:
                            current_log["Details"]["Subject"]["Account Name"] = line.split(":", 1)[1].strip()
                     elif "Account Domain:" in line:
                            current_log["Details"]["Subject"]["Account Domain"] = line.split(":", 1)[1].strip()
                     elif "Logon ID:" in line:
                            current_log["Details"]["Subject"]["Logon ID"] = line.split(":", 1)[1].strip()

                     elif line.startswith("Object"):
                     # 初始化"Object"子项
                            current_log["Details"]["Object"] = {}
                     elif "Object Server:" in line:
                            current_log["Details"]["Object"]["Object Server"] = line.split(":", 1)[1].strip()
                     elif "Object Type:" in line:
                            current_log["Details"]["Object"]["Object Type"] = line.split(":", 1)[1].strip()
                     elif "Object Name:" in line:
                            current_log["Details"]["Object"]["Object Name"] = line.split(":", 1)[1].strip()
                     elif "Handle ID:" in line:
                            current_log["Details"]["Object"]["Handle ID"] = line.split(":", 1)[1].strip()

                     elif line.startswith("Process Information"):
                            # 初始化"Process Information"子项
                            current_log["Details"]["Process Information"] = {}
                     elif "Process ID:" in line:
                            current_log["Details"]["Process Information"]["Process ID"] = line.split(":", 1)[1].strip()
                     elif "Process Name:" in line:
                            current_log["Details"]["Process Information"]["Process Name"] = line.split(":", 1)[1].strip()

                     elif line.startswith("Access Request Information"):
                            # 初始化"Access Request Information"子项
                            current_log["Details"]["Access Request Information"] = {}
                     elif "Transaction ID:" in line:
                            current_log["Details"]["Access Request Information"]["Transaction ID"] = line.split(":", 1)[1].strip()
                     elif "Accesses:" in line:
                            accesses = []
                            while "Accesses:" in line or "Access Mask:" not in line:
                                   accesses.append(line.strip())
                                   line = next(file).strip()
                            current_log["Details"]["Access Request Information"]["Accesses"] = accesses
                     elif "Access Mask:" in line:
                            current_log["Details"]["Access Request Information"]["Access Mask"] = line.split(":", 1)[1].strip()
                     elif "Privileges Used for Access Check:" in line:
                            current_log["Details"]["Access Request Information"]["Privileges Used for Access Check"] = line.split(":", 1)[1].strip()
                     elif "Restricted SID Count:" in line:
                            current_log["Details"]["Access Request Information"]["Restricted SID Count"] = line.split(":", 1)[1].strip()

       # 将最后一条日志条目添加到列表中
       if current_log:
              logs.append(current_log)

       # 将所有日志写入JSON文件
       with open(output_path, "w", encoding="utf-8") as json_file:
              json.dump(logs, json_file, ensure_ascii=False, indent=4)

       print(f"日志已成功写入 {output_path} 文件。")

def preprocess_linux():
       pass