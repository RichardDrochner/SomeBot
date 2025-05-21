import logging
import json
import asyncio
import aiohttp
import os
import ollama
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, List, Optional

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Variables from the .env file
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')
MODEL_HUMOR_PATH = os.getenv('MODEL_HUMOR')

if not DISCORD_WEBHOOK_URL:
    raise ValueError("DISCORD_WEBHOOK_URL is missing in the .env file.")
if not MODEL_HUMOR_PATH:
    raise ValueError("MODEL_HUMOR_PATH is missing in the .env file.")

def load_security_logs(log_path: str) -> List[Dict]:
    """Load and validate security logs from file"""
    try:
        if not Path(log_path).exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")

        with open(log_path, "r") as file:
            data = json.load(file)

        if not isinstance(data, (dict, list)):
            raise ValueError("Invalid log format: expected JSON object or array")

        return data if isinstance(data, list) else [data]

    except Exception as e:
        logging.error(f"Error loading {log_path}: {str(e)}")
        return []

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

def build_prompt_with_logs(logs: List[Dict]) -> str:
    try:
        # Read the humor base from file (contains the SYSTEM prompt)
        humor_base = ""
        if Path(MODEL_HUMOR_PATH).exists():
            with open(MODEL_HUMOR_PATH, "r") as f:
                humor_base = f.read().strip()

        prompt_parts = [
            "You are a sarcastic security assistant.",
            humor_base,
            "Here are the vulnerabilities that need your sarcastic expertise:"
        ]

        for log in logs:
            if not isinstance(log, dict):
                continue

            # Bandit report processing
            if log.get("scan_type") == "Bandit":
                metrics = log.get("metrics", {}).get("_totals", {})
                prompt_parts.append(
                    f"\n## Bandit Results\n"
                    f"- Files scanned: {metrics.get('loc', 'N/A')} lines\n"
                    f"- Issues found: {len(log.get('issues', []))}\n"
                )
                for issue in log.get("issues", []):
                    prompt_parts.append(
                        f"\n### {issue.get('severity', 'UNKNOWN')} severity\n"
                        f"Location: {issue.get('location', 'unknown')}\n"
                        f"Code:\n```python\n{issue.get('code', '')}\n```"
                    )

            # Dependency-Check processing
            elif log.get("scan_type") == "Dependency-Check":
                summary = log.get("summary", {})
                prompt_parts.append(
                    f"\n## Dependency Check Results\n"
                    f"- Dependencies: {summary.get('totalDependencies', 0)}\n"
                    f"- Vulnerabilities: {summary.get('totalVulnerabilities', 0)}\n"
                )
                for vuln in log.get("vulnerabilities", []):
                    prompt_parts.append(
                        f"\n### {vuln.get('severity', 'MEDIUM')}\n"
                        f"Package: {vuln.get('package', 'unknown')}\n"
                        f"CWEs: {', '.join(vuln.get('cwe', [])) or 'None'}"
                    )

        prompt_parts.extend([
            "\nNow provide sarcastic analysis with:",
            "- Gordon Ramsay-level criticism",
            "- Stand-up comedian timing",
            "- Bonus points for pop culture references!"
        ])

        return "\n".join(prompt_parts)

    except Exception as e:
        logging.error(f"Prompt generation failed: {str(e)}")
        return ""

def get_available_models() -> List[str]:
    """Get list of available model names"""
    try:
        response = ollama.list()
        # Handle both old and new API response formats
        if 'models' in response:
            return [model.get('model', model.get('name', 'unknown'))
                   for model in response['models']]
        return []
    except Exception as e:
        logging.error(f"Failed to get models: {e}")
        return []

async def generate_with_ollama(prompt: str, model: str = "llama3") -> Optional[str]:
    """Generate analysis using Ollama"""
    try:
        # Get available models
        available_models = get_available_models()
        logging.debug(f"Available models: {available_models}")

        if not available_models:
            raise ValueError("No models available - run 'ollama pull llama3' first")

        if model not in available_models:
            # Try with the first available model
            model = available_models[0]
            logging.warning(f"Requested model not found, using {model} instead")

        response = ollama.generate(
            model=model,
            prompt=prompt,
            stream=False
        )
        return response.get("response")
    except Exception as e:
        logging.error(f"AI generation failed: {str(e)}")
        return "I tried to be witty but crashed harder than your last deployment."


# Clean output for Discord
def clean_discord_message(text, max_length=1900):
    """Clean and format message for Discord"""
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
    while True:
        try:
            logging.basicConfig(level=logging.INFO)
            bandit_report = load_security_logs("downloaded-reports/bandit_report.json")
            dependency_check_report = load_security_logs("downloaded-reports/reports/dependency-check-report.json")
            #trivy_logs = load_trivy_logs()
            logs = [log for logs in [bandit_report, dependency_check_report] for log in logs]

            prompt = build_prompt_with_logs(logs)
            logging.info("Generated prompt for Ollama.")

            response = await generate_with_ollama(prompt)
            print("Ollama response:", response)

            final_message = clean_discord_message(response)
            await send_discord_message_async(final_message)

            await asyncio.sleep(3600)  # Run every hour
        except Exception as e:
            print(f"Error: {e}")
            await asyncio.sleep(60)



if __name__ == "__main__":
    asyncio.run(main())
