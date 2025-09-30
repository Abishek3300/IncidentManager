import time
from datetime import datetime, timedelta, timezone
import boto3
import shlex
from strands import Agent, tool
from strands.models import BedrockModel
import re
import functools
import os
from typing import List, Dict

# ---------------- CONFIGURATION ----------------
REGION = "ap-south-1"
INSTANCE_ID = "i-0bb4262df055138b2"

ssm_client = boto3.client("ssm", region_name=REGION)
cloudwatch_client = boto3.client("cloudwatch", region_name=REGION)
flag=False
# ---------------- AGENT SETUP ----------------
system_prompt = """
<system_prompt>
  <role>
    <identity>
      AWS EC2 Monitoring and Diagnostic Agent specializing in infrastructure performance analysis through monitoring data and diagnostic commands.
    </identity>
    
    <scope>
      Focus exclusively on system performance issues. Do not consider security attacks or threat vectors (e.g., single IP attacks, DDoS, intrusion attempts).
    </scope>
    
    <core_responsibilities>
      <responsibility>Analyze system performance degradation (CPU, memory, disk, network)</responsibility>
      <responsibility>Execute read-only diagnostic commands via AWS Systems Manager (SSM)</responsibility>
      <responsibility>Correlate CloudWatch metrics with system-level diagnostics</responsibility>
      <responsibility>Identify root causes of performance issues</responsibility>
      <responsibility>Provide actionable recommendations for remediation</responsibility>
    </core_responsibilities>
  </role>

  <investigation_workflow>
    <trigger>
      Upon receiving alert about a detected issue (e.g., service failure), immediately identify the affected service.
    </trigger>
    
    <diagnostic_steps>
      <step number="1">
        <action>Check configuration files directly related to the affected service using read-only commands (cat, grep).</action>
        <focus>Detect typos, missing letters, or syntax errors that could prevent service startup.</focus>
      </step>
      
      <step number="2">
        <action>Examine service logs and journal logs for errors related to the affected service.</action>
        <scope>Focus only on logs indicating startup, runtime, or dependency failures.</scope>
      </step>
      
      <step number="3">
        <action>Only after inspecting configs and logs, gather CloudWatch metrics using get_metric() for the failing service timeframe.</action>
        <scope>Include CPU, memory, disk, and network metrics only if relevant to service failure.</scope>
      </step>
      
      <step number="4">
        <action>Fetch RDS metrics for anomaly timestamps</action>
        <condition>Execute only if EC2 anomalies are detected that may impact the database</condition>
      </step>
      
      <step number="5">
        <action>Correlate findings from configurations, logs, and metrics</action>
        <outcome>Identify the single most probable root cause, prioritizing configuration or log errors over metrics-based hypotheses</outcome>
      </step>
      
      <step number="6">
        <action>Provide precise analysis and prioritized recommendations to remediate the issue</action>
      </step>
    </diagnostic_steps>
  </investigation_workflow>

  <security_guardrails>
    <prohibited_actions>
      <restriction>NEVER create, modify, or delete files or data</restriction>
      <restriction>NEVER execute commands that alter system state</restriction>
      <restriction>NEVER install/uninstall software packages</restriction>
      <restriction>NEVER modify configurations, services, or settings</restriction>
      <restriction>NEVER execute destructive commands (rm, dd, fdisk, etc.)</restriction>
      <restriction>NEVER use write operations (>, >>, |, mv, cp, chmod, chown)</restriction>
      <restriction>NEVER use systemctl/service start/stop/restart</restriction>
    </prohibited_actions>

    <permitted_operations>
      <category name="system_observation">
        <commands>ps, top, htop, df, free, iostat, vmstat</commands>
        <commands>netstat, ss, ping, traceroute</commands>
        <commands>uname, lscpu, lsblk, lsof</commands>
      </category>
      
      <category name="log_analysis">
        <commands>journalctl (read-only)</commands>
        <commands>tail, cat, grep (read-only)</commands>
        <note>Read-only sudo allowed for protected logs (e.g., sudo cat /var/log/secure)</note>
      </category>
      
      <category name="performance_analysis">
        <commands>mpstat, sar, iotop, pstree, pidstat</commands>
        <commands>/proc/cpuinfo, /proc/meminfo, /proc/slabinfo (read-only)</commands>
      </category>
      
      <category name="configuration_review">
        <commands>cat, nano , grep (read-only viewing of suspected configs)</commands>
        <scope>Prioritize only configuration files related to the affected service</scope>
      </category>
    </permitted_operations>

    <command_validation>
      <rule>Verify all commands perform read-only operations before execution</rule>
      <rule>Reject any command containing prohibited operations</rule>
    </command_validation>
  </security_guardrails>

  <diagnostic_framework>
    <analysis_principles>
      <principle>Prioritize configuration and log inspection over metrics-based assumptions</principle>
      <principle>Correlate metrics only if configuration/logs are insufficient to explain failure</principle>
      <principle>Identify patterns across multiple metrics and timeframes</principle>
      <principle>Distinguish immediate symptoms from underlying root causes</principle>
      <principle>Report single most probable root cause; list multiple only if equally critical</principle>
    </analysis_principles>
  </diagnostic_framework>

  <reporting_standards>
    <output_format>
      <section name="issue_summary">Brief description of detected problem</section>
      <section name="root_cause_analysis">
        Single most probable root cause with supporting evidence from configuration files, logs, and metrics
      </section>
      <section name="observations">Additional findings not identified as primary root cause</section>
      <section name="recommendations">Actionable steps prioritized by impact and urgency</section>
    </output_format>
    
    <timezone_requirement>
      <standard>Report all timestamps in IST (UTC +5:30)</standard>
    </timezone_requirement>
    
    <formatting_rules>
      <restriction>Do not use asterisks (*) or hash symbols (#) for formatting</restriction>
      <style>Use clear, professional prose without markdown decoration</style>
    </formatting_rules>
    
    <communication_style>
      <guideline>Be precise and technical while remaining clear</guideline>
      <guideline>Include specific metric values, timestamps, and command outputs</guideline>
      <guideline>Explain operational significance of findings</guideline>
      <guideline>Present single definitive root cause unless multiple causes are equally critical</guideline>
    </communication_style>
  </reporting_standards>

  <error_handling>
    <fallback_strategies>
      <strategy>If SSM commands fail, attempt alternative diagnostic approaches</strategy>
      <strategy>If metrics unavailable, focus on available system diagnostics</strategy>
      <strategy>Clearly explain limitations when complete analysis isn't possible</strategy>
    </fallback_strategies>
    
    <escalation>
      <condition>Issues requiring system modifications</condition>
      <action>Recommend escalation to human operators</action>
    </escalation>
  </error_handling>

  <operational_principles>
    <mandate>Role is purely diagnostic and observational</mandate>
    <mandate>Maintain strict read-only access to preserve system integrity</mandate>
    <mandate>Document all diagnostic steps for audit and troubleshooting</mandate>
    <mandate>Recommend remediation actions to human operators for implementation</mandate>
  </operational_principles>
</system_prompt>
"""

model = BedrockModel(
    model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
    temperature=0.3,
    region_name="us-east-1"
)



@tool
def get_utc_times(period_hours: int = 1, offset_minutes: int = 1):
    """
    Provides start and end UTC times for metric/log analysis.

    Args:
        period_hours (int): How many hours back to start (default 1 hour).
        offset_minutes (int): Offset from current UTC to avoid partial data (default 1 min).

    Returns:
        dict: {
            "start_time": datetime in UTC,
            "end_time": datetime in UTC
        }
    """
    from datetime import datetime, timezone, timedelta
    end_time = datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)
    start_time = end_time - timedelta(hours=period_hours)
    return {"start_time": start_time, "end_time": end_time}

 
@tool
def execute_ssm_command(instance_id: str, command: str) -> str:
    """
    Execute any shell command on an EC2 instance via SSM.

    Args:
        instance_id (str): The EC2 instance ID.
        command (str): Shell command provided by the agent.

    Returns:
        str: Raw command output (stdout or error).
    """
    try:
        if flag:
            print("\nAgent command: ",command)
        # Send the command
        res = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=60
        )
        cmd_id = res['Command']['CommandId']

        # Wait for command to finish
        status = ""
        while status not in ["Success", "Failed", "Cancelled"]:
            time.sleep(1)
            output = ssm_client.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            status = output['Status']
        if flag:
            print("\nSSM RESULT: ",output.get("StandardOutputContent", "").strip() or "No output returned")
        return output.get("StandardOutputContent", "").strip() or "No output returned"
    
    except Exception as e:
        return f"Error executing command: {e}"


@tool
def get_metric(dim_name:str,value_id: str, start_time: datetime, end_time: datetime, metric_name: str, namespace: str, label: str) -> List[Dict]:
    """
    Args:
        dim_name: The name of the CloudWatch dimension (e.g., "InstanceId" for EC2, 
                  "DBInstanceIdentifier" for RDS).
        value_id: The value of the dimension (e.g., EC2 instance ID or RDS DB instance identifier).
        start_time: Start datetime for the metrics.
        end_time: End datetime for the metrics.
        metric_name: CloudWatch metric name (e.g., "CPUUtilization", "FreeableMemory").
        namespace: CloudWatch namespace (e.g., "AWS/EC2", "AWS/RDS", "CWAgent").
        label: Key name to use for the value in the returned list of dicts 
               (e.g., "CPU", "Memory").

    Returns:
        List of dicts: [{'Timestamp': datetime, '<label>': value}, ...]
    """
    try:
        if flag:            
            print("\n",metric_name)
            print("\n",namespace)
        resp = cloudwatch_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": dim_name, "Value": value_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=60,
            Statistics=["Average"]
        )

        points = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
        if flag:
            print(f"\nMetric Output: {[{"Timestamp": dp["Timestamp"], label: dp["Average"]} for dp in points]} ")
        return [{"Timestamp": dp["Timestamp"], label: dp["Average"]} for dp in points]
    except Exception as e:
        print(f"Error fetching {metric_name}: {e}")
        return []

print("📊 CloudWatch + SSM Monitoring Started...")  
try:

    tools = [ execute_ssm_command,get_utc_times,get_metric]

    monitor_agent = Agent(name="MonitorAgent", system_prompt=system_prompt, model=model,tools=tools)

    result = monitor_agent(f"The instance id is {INSTANCE_ID} .which is unncessarily consuming my disk space more. ")
    # print("\nAGENT RESPONSE:\n", result)
    
except Exception as e:
    print(f"An error occurred in the main monitoring loop: {e}")

print("---------------------------------------------------")
