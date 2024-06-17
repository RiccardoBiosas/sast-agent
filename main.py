from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv
import os

load_dotenv()
openai_token = os.getenv('OPENAI_TOKEN')

llm = ChatOpenAI(api_key=openai_token)

template_one = PromptTemplate.from_template("""Act as a lead security engineer and perform a secure code review of the above {language_or_framework} snippet{optional_codebase_details}. The code snippet is in the directory path {target_pathname}. {scanner_name} flagged the above code as a potential `{vulnerability_type}` with the following explanation: `{vulnerability_analysis}`. The lines of code flagged by the {scanner_name} scanner are:
```
{vulnerable_code_lines}
```
Perform a security review, validate {scanner_name} finding and, if necessary, provide recommendations to improve the security posture of the codebase.""")

def main():
    language_or_framework = input("Enter the programming language or framework: ")
    optional_codebase_details = input("Enter any optional codebase details (press Enter if none): ")
    target_pathname = input("Enter the directory path of the code snippet: ")
    scanner_name = input("Enter the name of the scanner: ")
    vulnerability_type = input("Enter the potential vulnerability type: ")
    vulnerability_analysis = input("Enter the vulnerability analysis: ")
    vulnerable_code_lines = input("Enter the lines of code flagged as vulnerable: ")

    llm_input = template_one.format(
        language_or_framework=language_or_framework,
        optional_codebase_details=optional_codebase_details,
        target_pathname=target_pathname,
        scanner_name=scanner_name,
        vulnerability_type=vulnerability_type,
        vulnerability_analysis=vulnerability_analysis,
        vulnerable_code_lines=vulnerable_code_lines
    )

    response = llm.invoke(llm_input)
    print("\nSecurity Review:")
    print(response.content)

if __name__ == "__main__":
    main()