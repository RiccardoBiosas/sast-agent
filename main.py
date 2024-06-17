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

llm_input = template_one.format(language_or_framework="XML", optional_codebase_details='', target_pathname='Drawing/Examples/Android/OdaAndroidApp/AndroidManifest.xml', scanner_name='The CodeQL scanner',vulnerability_type='Android debuggable attribute enabled', vulnerability_analysis='he Android manifest file defines configuration settings for Android applications. In this file, the android:debuggable attribute of the application element can be used to define whether or not the application can be debugged. When set to true, this attribute will allow the application to be debugged even when running on a device in user mode.', vulnerable_code_lines='<application android:icon="@drawable/icon" android:label="@string/app_name" android:debuggable="true">')


response = llm.invoke(llm_input)
print(response.content)