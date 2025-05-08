import logging
import json
import asyncio
import aiohttp
import os
import ollama
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, List

class SecurityLogProcessor:
    def __init__(self, log_dir: str = "security_reports"):
        self.log_dir = Path(log_dir)

    def load_bandit_report(self) -> Dict:
        """Load and process Bandit JSON report"""
        bandit_file = self.log_dir / "bandit_report.json"
        with open(bandit_file) as f:
            report = json.load(f)

        # Extract key information
        processed = {
            "scan_type": "Bandit",
            "metrics": report.get("metrics", {}),
            "issues": []
        }

        for issue in report.get("results", []):
            processed["issues"].append({
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
                "type": issue.get("test_id"),
                "description": issue.get("issue_text"),
                "location": f"{issue.get('filename')}:{issue.get('line_number')}",
                "code": issue.get("code")
            })

        return processed

    def load_dependency_check_report(self) -> Dict:
        """Load and process Dependency-Check JSON report"""
        dep_file = self.log_dir / "dependency-check-report.json"
        with open(dep_file) as f:
            report = json.load(f)

        processed = {
            "scan_type": "Dependency-Check",
            "summary": report.get("summary", {}),
            "vulnerabilities": []
        }

        for vuln in report.get("dependencies", []):
            for v in vuln.get("vulnerabilities", []):
                processed["vulnerabilities"].append({
                    "severity": v.get("severity"),
                    "name": v.get("name"),
                    "description": v.get("description"),
                    "package": f"{vuln.get('fileName')} ({vuln.get('filePath')})",
                    "cwe": v.get("cwes", [])
                })

        return processed


# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Variables from the .env file
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

if not DISCORD_WEBHOOK_URL:
    raise ValueError("DISCORD_WEBHOOK_URL is missing in the .env file.")

# Load Trivy logs from file
def load_trivy_logs(log_path="trivy_output.json"):
    try:
        with open(log_path, "r") as file:
            raw_data = json.load(file)
            logging.debug(f"Raw Trivy log content: {json.dumps(raw_data, indent=2)}")

            vulnerabilities = []
            if isinstance(raw_data, dict) and "Results" in raw_data:
                for result in raw_data["Results"]:
                    vulns = result.get("Vulnerabilities", [])
                    if isinstance(vulns, list):
                        vulnerabilities.extend(vulns)
            elif isinstance(raw_data, dict) and "vulnerabilities" in raw_data:
                vulnerabilities = raw_data["vulnerabilities"]

            if not isinstance(vulnerabilities, list):
                logging.error("Log format error: Logs should be a list of dictionaries.")
                return []

            logging.info(f"Extracted {len(vulnerabilities)} vulnerability entries.")
            return vulnerabilities
    except Exception as e:
        logging.error(f"Error loading logs: {e}")
        return []


# Clean output for Discord
def clean_discord_message(text, max_length=1900):
    try:
        cleaned = text.encode("utf-8", "ignore").decode("utf-8").replace('\u0000', '')
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length] + "\n... (truncated)"
        return cleaned
    except Exception as e:
        logging.error(f"Error cleaning message: {e}")
        return ": Message could not be processed."

# Send to Discord
async def send_discord_message_async(message):
    try:
        payload = {"content": message}
        headers = {"Content-Type": "application/json"}

        logging.debug(f"Discord Payload: {json.dumps(payload)}")

        async with aiohttp.ClientSession() as session:
            async with session.post(DISCORD_WEBHOOK_URL, json=payload, headers=headers) as response:
                if response.status == 204:
                    logging.debug("Message sent to Discord.")
                else:
                    logging.error(f"Discord responded with status: {response.status}")
    except Exception as e:
        logging.error(f"Error sending to Discord: {e}")

# Main entry
async def main():
    try:
        processor = SecurityLogProcessor()
        reports: []
        if (processor.log_dir / "bandit_report.json").exists():
            reports.append(processor.load_bandit_report())
        if (processor.log_dir / "dependency-check-report.json").exists():
            reports.append(processor.load_dependency_check_report())

        logs = load_trivy_logs()
        if not logs:
            logging.error("No valid logs to process.")
            return

        reports.append(logs)

        prompt = build_prompt_with_logs(reports)
        if not prompt:
            logging.error("Failed to build prompt.")
            return

        response = await send_prompt_to_deepseek(prompt, temperature=1.1)
        final_message = clean_discord_message(response)
        await send_discord_message_async(final_message)

    except Exception as e:
        logging.error(f"Error in main process: {e}")

if __name__ == "__main__":
    asyncio.run(main())