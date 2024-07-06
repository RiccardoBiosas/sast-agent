import json
import argparse
import subprocess
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv
import os

load_dotenv()
openai_token = os.getenv('OPENAI_TOKEN')

llm = ChatOpenAI(api_key=openai_token)

template_one = PromptTemplate.from_template("""
                                                {main_code_snippet}
                                            Act as a lead security engineer and perform a secure code review of the above {language_or_framework} snippet{optional_codebase_details}. The code snippet is in the directory path {target_pathname}. {scanner_name} flagged the above code as a potential `{vulnerability_type}` with the following explanation: `{vulnerability_analysis}`. The lines of code flagged by the {scanner_name} scanner are:
                                                ```
                                                {vulnerable_code_lines}
                                                ```
                                            Perform a security review, validate {scanner_name} finding and, if necessary, provide recommendations to improve the security posture of the codebase.
                                            """)

def run_bandit_docker(code_file):
    output_file = "sast_bandit.json"

    command = [
        "docker", "run", "--rm", "-v", f"{os.getcwd()}:/app", "ghcr.io/pycqa/bandit/bandit", f"/app/{code_file}",
        "-f", "json", "-o", f"/app/{output_file}"
    ]

    try:
        subprocess.check_call(command) # TODO: check why it always exits with status code error 1
    except:
        print('')

    try:
        with open(output_file, "r") as file:
            bandit_output = json.load(file)
        return bandit_output
    except subprocess.CalledProcessError as e:
        print(f"Error running Bandit: {e}")
        exit(1)
    finally:
        os.remove(output_file)

def process_bandit_output(bandit_output, verbose=False):
    for finding in bandit_output["results"]:
        main_code_snippet = finding["code"]
        language_or_framework = "Python"
        optional_codebase_details = ""
        target_pathname = finding["filename"]
        scanner_name = "Bandit"
        vulnerability_type = finding["test_id"]
        vulnerability_analysis = finding["issue_text"]
        vulnerable_code_lines = finding["code"]

        if verbose:
            print(f"Processing finding for {target_pathname}")
            print(f"Vulnerability type: {vulnerability_type}")
            print(f"Vulnerability analysis: {vulnerability_analysis}")
            print(f"Vulnerable code lines:\n{vulnerable_code_lines}")

        llm_input = template_one.format(
            main_code_snippet=main_code_snippet,
            language_or_framework=language_or_framework,
            optional_codebase_details=optional_codebase_details,
            target_pathname=target_pathname,
            scanner_name=scanner_name,
            vulnerability_type=vulnerability_type,
            vulnerability_analysis=vulnerability_analysis,
            vulnerable_code_lines=vulnerable_code_lines
        )

        response = llm.invoke(llm_input)
        print(f"\nSecurity Review for {target_pathname}:")
        print(response.content)

def main():
    parser = argparse.ArgumentParser(description="Process Bandit SAST scanner output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-c", "--code", required=True, help="Code file to scan with Bandit")
    args = parser.parse_args()

    code_file = args.code
    bandit_output = run_bandit_docker(code_file)
    process_bandit_output(bandit_output, args.verbose)

if __name__ == "__main__":
    main()