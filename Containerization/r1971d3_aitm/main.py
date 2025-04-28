import base64
import streamlit as st
import streamlit.components.v1 as components
from github import Github
from collections import defaultdict
import re
import os
from dotenv import load_dotenv
from openai import OpenAI
import requests
import json

from threat_model import create_threat_model_prompt, get_threat_model, get_threat_model_azure, get_threat_model_google, get_threat_model_mistral, get_threat_model_ollama, get_threat_model_anthropic, get_threat_model_lm_studio, get_threat_model_groq, json_to_markdown, get_image_analysis, create_image_analysis_prompt
from attack_tree import create_attack_tree_prompt, get_attack_tree, get_attack_tree_azure, get_attack_tree_mistral, get_attack_tree_ollama, get_attack_tree_anthropic, get_attack_tree_lm_studio, get_attack_tree_groq, get_attack_tree_google
from mitigations import create_mitigations_prompt, get_mitigations, get_mitigations_azure, get_mitigations_google, get_mitigations_mistral, get_mitigations_ollama, get_mitigations_anthropic, get_mitigations_lm_studio, get_mitigations_groq
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_azure, get_test_cases_google, get_test_cases_mistral, get_test_cases_ollama, get_test_cases_anthropic, get_test_cases_lm_studio, get_test_cases_groq
from dread import create_dread_assessment_prompt, get_dread_assessment, get_dread_assessment_azure, get_dread_assessment_google, get_dread_assessment_mistral, get_dread_assessment_ollama, get_dread_assessment_anthropic, get_dread_assessment_lm_studio, get_dread_assessment_groq, dread_json_to_markdown

from classes.threat_model_fl import ThreatModelCl
from classes.control_matrix_fl import ControlMatrixCl
from classes.attack_tree_fl import AttackTreeCl
from classes.mark_down_fl import MarkDownCl

# ------------------ Helper Functions ------------------ #
def get_ollama_models(ollama_endpoint):
    """
    Get list of available models from Ollama.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://host.docker.internal:11434')
        
    Returns:
        list: List of available model names
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/tags"
    
    try:
        response = requests.get(url, timeout=900)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        models_data = response.json()
        
        # Extract model names from the response
        model_names = [model['name'] for model in models_data['models']]
        if not model_names:
            st.warning("""No models found in Ollama. Please ensure you have:
1. Pulled at least one model using 'ollama pull <model_name>'
2. The model download completed successfully""")
            return ["local-model"]
        return model_names
            
    except requests.exceptions.ConnectionError:
        st.error("""Unable to connect to Ollama. Please ensure:
1. Ollama is installed and running
2. The endpoint URL is correct (default: http://host.docker.internal:11434)
3. No firewall is blocking the connection""")
        return ["local-model"]
    except requests.exceptions.Timeout:
        st.error("""Request to Ollama timed out. Please check:
1. Ollama is responding and not overloaded
2. Your network connection is stable
3. The endpoint URL is accessible""")
        return ["local-model"]
    except (KeyError, json.JSONDecodeError):
        st.error("""Received invalid response from Ollama. Please verify:
1. You're running a compatible version of Ollama
2. The endpoint URL is pointing to Ollama and not another service""")
        return ["local-model"]
    except Exception as e:
        st.error(f"""Unexpected error fetching Ollama models: {str(e)}
        
Please check:
1. Ollama is properly installed and running
2. You have pulled at least one model
3. You have sufficient system resources""")
        return ["local-model"]

# Function to get user input for the application description and key details
def get_input():
    input_text = st.text_area(
        label="Describe the application to be modelled",
        value=st.session_state.get('app_input', ''),
        placeholder="Enter your application details...",
        height=300,
        key="app_desc",
        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
    )

    st.session_state['app_input'] = input_text

    return input_text

def summarize_file(file_path, content):
    # Extract important parts of the file
    imports = re.findall(r'^import .*|^from .* import .*', content, re.MULTILINE)
    functions = re.findall(r'def .*\(.*\):', content)
    classes = re.findall(r'class .*:', content)

    summary = f"File: {file_path}\n"
    if imports:
        summary += "Imports:\n" + "\n".join(imports[:5]) + "\n"  # Limit to first 5 imports
    if functions:
        summary += "Functions:\n" + "\n".join(functions[:5]) + "\n"  # Limit to first 5 functions
    if classes:
        summary += "Classes:\n" + "\n".join(classes[:5]) + "\n"  # Limit to first 5 classes

    return summary

# Function to render Mermaid diagram
def mermaid(code: str, height: int = 500) -> None:
    components.html(
        f"""
        <pre class="mermaid" style="height: {height}px;">
            {code}
        </pre>

        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{ startOnLoad: true }});
        </script>
        """,
        height=height,
    )

def load_env_variables():
    # Try to load from .env file
    if os.path.exists('.env'):
        load_dotenv('.env')

    # Load other API keys if needed
    openai_api_key = os.getenv('OPENAI_API_KEY')
    if openai_api_key:
        st.session_state['openai_api_key'] = openai_api_key

    google_api_key = os.getenv('GOOGLE_API_KEY')
    if google_api_key:
        st.session_state['google_api_key'] = google_api_key

    # Add Ollama endpoint configuration
    ollama_endpoint = os.getenv('OLLAMA_ENDPOINT', 'http://host.docker.internal:11434')
    st.session_state['ollama_endpoint'] = ollama_endpoint

# Call this function at the start of your app
load_env_variables()

# ------------------ Streamlit UI Configuration ------------------ #

st.set_page_config(
    page_title="AI-enabled Theat Modelling",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------ Sidebar ------------------ #

# ------------------ Sidebar ------------------ #

st.sidebar.image("logo.png")

# Add instructions on how to use the app to the sidebar
st.sidebar.header("How to use AI-enabled Theat Modelling")

with st.sidebar:
    # Add model selection input field to the sidebar
    model_provider = st.selectbox(
        "Select your preferred model provider:",
        ["OpenAI API", "Google AI API", "Ollama"],
        key="model_provider",
        help="Select the model provider you would like to use. This will determine the models available for selection.",
    )

    if model_provider == "OpenAI API":
        # Add model selection input field to the sidebar
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["gpt-4o", "gpt-4o-mini", "o1", "o3-mini"],
            key="selected_model",
            help="GPT-4o and GPT-4o mini are OpenAI's latest models and are recommended."
        )

    if model_provider == "Google AI API":
        # Add model selection input field to the sidebar
        google_model = st.selectbox(
            "Select the model you would like to use:",
            ["gemini-2.0-flash", "gemini-1.5-pro"],
            key="selected_model",
        )

    if model_provider == "Ollama":
        # Fetch available models from Ollama using the endpoint from .env
        ollama_endpoint = st.session_state['ollama_endpoint']
        
        # Display the endpoint (read-only)
        st.text(f"Using Ollama endpoint: {ollama_endpoint}")
        
        # Fetch available models from Ollama
        available_models = get_ollama_models(ollama_endpoint)

        # Add model selection input field
        selected_model = st.selectbox(
            "Select the Ollama model you would like to use:",
            available_models if ollama_endpoint and ollama_endpoint.startswith(('http://', 'https://')) else ["local-model"],
            key="selected_model",
            help="Select the model you have pulled into your Ollama instance."
        )

# ------------------ Main App UI ------------------ #

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Threat Model", "Attack Tree", "Mitigations", "DREAD", "Test Cases", "PASTA"])

with tab1:
    st.markdown("""
A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to 
understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE methodology.
""")
    st.markdown("""---""")
    
    # Two column layout for the main app content
    col1, col2 = st.columns([1, 1])

    # Initialize app_input in the session state if it doesn't exist
    if 'app_input' not in st.session_state:
        st.session_state['app_input'] = ''

    # If model provider is OpenAI API and the model is gpt-4o or gpt-4o-mini
    with col1:
        if model_provider == "OpenAI API" and selected_model in ["gpt-4o", "gpt-4o-mini"]:
            uploaded_file = st.file_uploader("Upload architecture diagram", type=["jpg", "jpeg", "png"])

            if uploaded_file is not None:
                openai_api_key = st.session_state['openai_api_key']
                if not openai_api_key:
                    st.error("Please enter your OpenAI API key to analyse the image.")
                else:
                    if 'uploaded_file' not in st.session_state or st.session_state.uploaded_file != uploaded_file:
                        st.session_state.uploaded_file = uploaded_file
                        with st.spinner("Analysing the uploaded image..."):
                            def encode_image(uploaded_file):
                                return base64.b64encode(uploaded_file.read()).decode('utf-8')

                            base64_image = encode_image(uploaded_file)

                            image_analysis_prompt = create_image_analysis_prompt()

                            try:
                                openai_api_key = st.session_state['openai_api_key']
                                image_analysis_output = get_image_analysis(openai_api_key, selected_model, image_analysis_prompt, base64_image)
                                if image_analysis_output and 'choices' in image_analysis_output and image_analysis_output['choices'][0]['message']['content']:
                                    image_analysis_content = image_analysis_output['choices'][0]['message']['content']
                                    st.session_state.image_analysis_content = image_analysis_content
                                    # Update app_input session state
                                    st.session_state['app_input'] = image_analysis_content
                                else:
                                    st.error("Failed to analyze the image. Please check the API key and try again.")
                            except KeyError as e:
                                st.error("Failed to analyze the image. Please check the API key and try again.")
                                print(f"Error: {e}")
                            except Exception as e:
                                st.error("An unexpected error occurred while analyzing the image.")
                                print(f"Error: {e}")

        # Use the get_input() function to get the application description and GitHub URL
        app_input = get_input()
        # Update session state only if the text area content has changed
        if app_input != st.session_state['app_input']:
            st.session_state['app_input'] = app_input

    # Ensure app_input is always up to date in the session state
    app_input = st.session_state['app_input']



        # Create input fields for additional details
    with col2:
            app_type = st.selectbox(
                label="Select the application type",
                options=[
                    "Web application",
                    "Mobile application",
                    "Desktop application",
                    "Cloud application",
                    "IoT application",
                    "Other",
                ],
                key="app_type",
            )

            sensitive_data = st.selectbox(
                label="What is the highest sensitivity level of the data processed by the application?",
                options=[
                    "Top Secret",
                    "Secret",
                    "Confidential",
                    "Restricted",
                    "Unclassified",
                    "None",
                ],
                key="sensitive_data",
            )

        # Create input fields for internet_facing and authentication
            internet_facing = st.selectbox(
                label="Is the application internet-facing?",
                options=["Yes", "No"],
                key="internet_facing",
            )

            authentication = st.multiselect(
                "What authentication methods are supported by the application?",
                ["SSO", "MFA", "OAUTH2", "Basic", "None"],
                key="authentication",
            )



    # ------------------ Threat Model Generation ------------------ #

    # Create a submit button for Threat Modelling
    threat_model_submit_button = st.button(label="Generate Threat Model")

    # If the Generate Threat Model button is clicked and the user has provided an application description
    if threat_model_submit_button and st.session_state.get('app_input'):
        app_input = st.session_state['app_input']  # Retrieve from session state
        # Generate the prompt using the create_prompt function
        threat_model_prompt = create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

        # Show a spinner while generating the threat model
        with st.spinner("Analysing potential threats..."):
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    # Call the relevant get_threat_model function with the generated prompt
                    if model_provider == "OpenAI API":
                        openai_api_key = st.session_state['openai_api_key']
                        model_output = get_threat_model(openai_api_key, selected_model, threat_model_prompt)
                    elif model_provider == "Google AI API":
                        google_api_key = st.session_state['google_api_key']
                        model_output = get_threat_model_google(google_api_key, google_model, threat_model_prompt)
                    elif model_provider == "Ollama":
                        model_output = get_threat_model_ollama(st.session_state['ollama_endpoint'], selected_model, threat_model_prompt)

                    # Access the threat model and improvement suggestions from the parsed content
                    threat_model = model_output.get("threat_model", [])
                    improvement_suggestions = model_output.get("improvement_suggestions", [])

                    # Save the threat model to the session state for later use in mitigations
                    st.session_state['threat_model'] = threat_model
                    break  # Exit the loop if successful
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        st.error(f"Error generating threat model after {max_retries} attempts: {e}")
                        threat_model = []
                        improvement_suggestions = []
                    else:
                        st.warning(f"Error generating threat model. Retrying attempt {retry_count+1}/{max_retries}...")

        # Convert the threat model JSON to Markdown
        markdown_output = json_to_markdown(threat_model, improvement_suggestions)

        # Display the threat model in Markdown
        st.markdown(markdown_output)

        # Add a button to allow the user to download the output as a Markdown file
        st.download_button(
            label="Download Threat Model",
            data=markdown_output,  # Use the Markdown output
            file_name="stride_gpt_threat_model.md",
            mime="text/markdown",
       )

# If the submit button is clicked and the user has not provided an application description
if threat_model_submit_button and not st.session_state.get('app_input'):
    st.error("Please enter your application details before submitting.")



# ------------------ Attack Tree Generation ------------------ #

with tab2:
    st.markdown("""
Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format, 
with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches. This helps in understanding system 
vulnerabilities and prioritising mitigation efforts.
""")
    st.markdown("""---""")
    if model_provider == "Mistral API":
        st.warning("⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.")
    else:
        if model_provider in ["Ollama", "LM Studio Server"]:
            st.warning("⚠️ Users may encounter syntax errors when generating attack trees using local LLMs. Experiment with different local LLMs to assess their output quality, or consider using a hosted model provider to generate attack trees.")
        
        # Create a submit button for Attack Tree
        attack_tree_submit_button = st.button(label="Generate Attack Tree")
        
        # If the Generate Attack Tree button is clicked and the user has provided an application description
        if attack_tree_submit_button and st.session_state.get('app_input'):
            app_input = st.session_state.get('app_input')
            # Generate the prompt using the create_attack_tree_prompt function
            attack_tree_prompt = create_attack_tree_prompt(app_type, authentication, internet_facing, sensitive_data, app_input)

            # Show a spinner while generating the attack tree
            with st.spinner("Generating attack tree..."):
                try:
                    # Call the relevant get_attack_tree function with the generated prompt
                    if model_provider == "OpenAI API":
                        openai_api_key = st.session_state['openai_api_key']
                        mermaid_code = get_attack_tree(openai_api_key, selected_model, attack_tree_prompt)
                    elif model_provider == "Google AI API":
                        google_api_key = st.session_state['google_api_key']
                        mermaid_code = get_attack_tree_google(google_api_key, google_model, attack_tree_prompt)
                    elif model_provider == "Ollama":
                        mermaid_code = get_mitigations_ollama(st.session_state['ollama_endpoint'], selected_model, attack_tree_prompt)
                    # Display the generated attack tree code
                    st.write("Attack Tree Code:")
                    st.code(mermaid_code)

                    # Visualise the attack tree using the Mermaid custom component
                    st.write("Attack Tree Diagram Preview:")
                    mermaid(mermaid_code)
                    
                    col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                    
                    with col1:              
                        # Add a button to allow the user to download the Mermaid code
                        st.download_button(
                            label="Download Diagram Code",
                            data=mermaid_code,
                            file_name="attack_tree.md",
                            mime="text/plain",
                            help="Download the Mermaid code for the attack tree diagram."
                        )

                    with col2:
                        # Add a button to allow the user to open the Mermaid Live editor
                        mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")
                    
                    with col3:
                        # Blank placeholder
                        st.write("")
                    
                    with col4:
                        # Blank placeholder
                        st.write("")
                    
                    with col5:
                        # Blank placeholder
                        st.write("")

                except Exception as e:
                    st.error(f"Error generating attack tree: {e}")


# ------------------ Mitigations Generation ------------------ #

with tab3:
    st.markdown("""
Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or
countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance
the security posture of the application and protect against potential attacks.
""")
    st.markdown("""---""")
    
    # Create a submit button for Mitigations
    mitigations_submit_button = st.button(label="Suggest Mitigations")

    # If the Suggest Mitigations button is clicked and the user has identified threats
    if mitigations_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            # Generate the prompt using the create_mitigations_prompt function
            mitigations_prompt = create_mitigations_prompt(threats_markdown)

            # Show a spinner while suggesting mitigations
            with st.spinner("Suggesting mitigations..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_mitigations function with the generated prompt
                        if model_provider == "OpenAI API":
                            openai_api_key = st.session_state['openai_api_key']
                            mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt)
                        elif model_provider == "Google AI API":
                            google_api_key = st.session_state['google_api_key']
                            mitigations_markdown = get_mitigations_google(google_api_key, google_model, mitigations_prompt)
                        elif model_provider == "Ollama":
                            mitigations_markdown = get_mitigations_ollama(st.session_state['ollama_endpoint'], selected_model, mitigations_prompt)

                        # Display the suggested mitigations in Markdown
                        st.markdown(mitigations_markdown)
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(f"Error suggesting mitigations after {max_retries} attempts: {e}")
                            mitigations_markdown = ""
                        else:
                            st.warning(f"Error suggesting mitigations. Retrying attempt {retry_count+1}/{max_retries}...")
            
            st.markdown("")

            # Add a button to allow the user to download the mitigations as a Markdown file
            st.download_button(
                label="Download Mitigations",
                data=mitigations_markdown,
                file_name="mitigations.md",
                mime="text/markdown",
            )
        else:
            st.error("Please generate a threat model first before suggesting mitigations.")

# ------------------ DREAD Risk Assessment Generation ------------------ #
with tab4:
    st.markdown("""
DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, 
**R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and 
focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
""")
    st.markdown("""---""")
    
    # Create a submit button for DREAD Risk Assessment
    dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")
    # If the Generate DREAD Risk Assessment button is clicked and the user has identified threats
    if dread_assessment_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            # Generate the prompt using the create_dread_assessment_prompt function
            dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown)
            # Show a spinner while generating DREAD Risk Assessment
            with st.spinner("Generating DREAD Risk Assessment..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_dread_assessment function with the generated prompt
                        if model_provider == "OpenAI API":
                            openai_api_key = st.session_state['openai_api_key']
                            dread_assessment = get_dread_assessment(openai_api_key, selected_model, dread_assessment_prompt)
                        elif model_provider == "Google AI API":
                            google_api_key = st.session_state['google_api_key']
                            dread_assessment = get_dread_assessment_google(google_api_key, google_model, dread_assessment_prompt)
                        elif model_provider == "Ollama":
                            dread_assessment = get_dread_assessment_ollama(st.session_state['ollama_endpoint'], selected_model, dread_assessment_prompt)
                        
                        # Save the DREAD assessment to the session state for later use in test cases
                        st.session_state['dread_assessment'] = dread_assessment
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(f"Error generating DREAD risk assessment after {max_retries} attempts: {e}")
                            dread_assessment = []
                        else:
                            st.warning(f"Error generating DREAD risk assessment. Retrying attempt {retry_count+1}/{max_retries}...")
            # Convert the DREAD assessment JSON to Markdown
            dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
            # Display the DREAD assessment in Markdown
            st.markdown(dread_assessment_markdown)
            # Add a button to allow the user to download the test cases as a Markdown file
            st.download_button(
                label="Download DREAD Risk Assessment",
                data=dread_assessment_markdown,
                file_name="dread_assessment.md",
                mime="text/markdown",
            )
        else:
            st.error("Please generate a threat model first before requesting a DREAD risk assessment.")


# ------------------ Test Cases Generation ------------------ #

with tab5:
    st.markdown("""
Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and 
addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application 
behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test 
scenarios.
""")
    st.markdown("""---""")
                
    # Create a submit button for Test Cases
    test_cases_submit_button = st.button(label="Generate Test Cases")

    # If the Generate Test Cases button is clicked and the user has identified threats
    if test_cases_submit_button:
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            # Generate the prompt using the create_test_cases_prompt function
            test_cases_prompt = create_test_cases_prompt(threats_markdown)

            # Show a spinner while generating test cases
            with st.spinner("Generating test cases..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call to the relevant get_test_cases function with the generated prompt
                        if model_provider == "OpenAI API":
                            openai_api_key = st.session_state['openai_api_key']
                            test_cases_markdown = get_test_cases(openai_api_key, selected_model, test_cases_prompt)
                        elif model_provider == "Google AI API":
                            google_api_key = st.session_state['google_api_key']
                            test_cases_markdown = get_test_cases_google(google_api_key, google_model, test_cases_prompt)
                        elif model_provider == "Ollama":
                            test_cases_markdown = get_test_cases_ollama(st.session_state['ollama_endpoint'], selected_model, test_cases_prompt)

                        # Display the suggested mitigations in Markdown
                        st.markdown(test_cases_markdown)
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(f"Error generating test cases after {max_retries} attempts: {e}")
                            test_cases_markdown = ""
                        else:
                            st.warning(f"Error generating test cases. Retrying attempt {retry_count+1}/{max_retries}...")
            
            st.markdown("")

            # Add a button to allow the user to download the test cases as a Markdown file
            st.download_button(
                label="Download Test Cases",
                data=test_cases_markdown,
                file_name="test_cases.md",
                mime="text/markdown",
            )
        else:
            st.error("Please generate a threat model first before requesting test cases.")

# Initialize session state for PASTA tab if not already present
if 'pasta_app_input' not in st.session_state:
    st.session_state['pasta_app_input'] = ''
if 'pasta_app_type' not in st.session_state:
    st.session_state['pasta_app_type'] = 'Web application'
if 'pasta_sensitive_data' not in st.session_state:
    st.session_state['pasta_sensitive_data'] = 'Unclassified'
if 'pasta_pam' not in st.session_state:
    st.session_state['pasta_pam'] = 'No'
if 'pasta_internet_facing' not in st.session_state:
    st.session_state['pasta_internet_facing'] = 'No'
if 'pasta_authentication' not in st.session_state:
    st.session_state['pasta_authentication'] = []
if 'pasta_threat_model_output' not in st.session_state:
    st.session_state['pasta_threat_model_output'] = ''
if 'pasta_control_matrix_output' not in st.session_state:
    st.session_state['pasta_control_matrix_output'] = ''
if 'pasta_attack_tree_output' not in st.session_state:
    st.session_state['pasta_attack_tree_output'] = ''

# PASTA Tab
with tab6:
    # Get application description from the user
    pasta_app_input = st.text_area(
        label="Describe the application to be modelled",
        value=st.session_state['pasta_app_input'],
        placeholder="Enter your application details...",
        height=150,
        key="pasta_app_input_area",
        help="Please provide a detailed description of the application, including the purpose, technologies used, and other relevant information.",
        on_change=lambda: st.session_state.update(pasta_app_input=st.session_state.pasta_app_input_area)
    )

    # Create two columns layout for input fields
    col1, col2 = st.columns(2)

    # Create input fields for app_type, sensitive_data and pam
    with col1:
        pasta_app_type = st.selectbox(
            label="Select the application type",
            options=[
                "Web application",
                "Mobile application",
                "Desktop application",
                "Cloud application",
                "IoT application",
                "Other",
            ],
            key="pasta_app_type_select",
            index=["Web application", "Mobile application", "Desktop application", "Cloud application", "IoT application", "Other"].index(st.session_state['pasta_app_type']),
            on_change=lambda: st.session_state.update(pasta_app_type=st.session_state.pasta_app_type_select)
        )

        pasta_sensitive_data = st.selectbox(
            label="What is the highest sensitivity level of the data processed by the application?",
            options=[
                "Top Secret",
                "Secret", 
                "Confidential",
                "Restricted",
                "Unclassified",
                "None",
            ],
            key="pasta_sensitive_data_select",
            index=["Top Secret", "Secret", "Confidential", "Restricted", "Unclassified", "None"].index(st.session_state['pasta_sensitive_data']),
            on_change=lambda: st.session_state.update(pasta_sensitive_data=st.session_state.pasta_sensitive_data_select)
        )

        pasta_pam = st.selectbox(
            label="Are privileged accounts stored in a Privileged Access Management (PAM) solution?",
            options=["Yes", "No"],
            key="pasta_pam_select",
            index=["Yes", "No"].index(st.session_state['pasta_pam']),
            on_change=lambda: st.session_state.update(pasta_pam=st.session_state.pasta_pam_select)
        )

    # Create input fields for internet_facing and authentication
    with col2:
        pasta_internet_facing = st.selectbox(
            label="Is the application internet-facing?",
            options=["Yes", "No"],
            key="pasta_internet_facing_select",
            index=["Yes", "No"].index(st.session_state['pasta_internet_facing']),
            on_change=lambda: st.session_state.update(pasta_internet_facing=st.session_state.pasta_internet_facing_select)
        )

        pasta_authentication = st.multiselect(
            "What authentication methods are supported by the application?",
            ["SSO", "MFA", "OAUTH2", "Basic", "None"],
            default=st.session_state['pasta_authentication'],
            key="pasta_authentication_select",
            on_change=lambda: st.session_state.update(pasta_authentication=st.session_state.pasta_authentication_select)
        )

    # Threat Model, Security Controls, and Attack Tree sub-tabs
    pasta_tab1, pasta_tab2, pasta_tab3 = st.tabs(["Threat Model", "Security Controls", "MITRE Attack Tree"])
    
    # Initialize classes
    threat_model_obj = ThreatModelCl()
    control_matrix_obj = ControlMatrixCl()
    attack_tree_obj = AttackTreeCl()
    markdown_obj = MarkDownCl()

    # Threat Model Sub-Tab
    with pasta_tab1:
        # Display previously generated threat model if exists
        if st.session_state['pasta_threat_model_output']:
            st.markdown(st.session_state['pasta_threat_model_output'])
            st.download_button(
                label="Download Threat Model",
                data=st.session_state['pasta_threat_model_output'],
                file_name="pasta_gpt_threat_model.md",
                mime="text/markdown",
            )

        if st.button("Generate Threat Model", key="pasta_threat_model_btn"):
            if not st.session_state['pasta_app_input']:
                st.error("Please enter your application details before submitting.")
            else:
                # Generate the prompt using the create_prompt function
                threat_model_prompt = threat_model_obj.create_threat_model_prompt(
                    app_type=st.session_state['pasta_app_type'], 
                    authentication=st.session_state['pasta_authentication'], 
                    internet_facing=st.session_state['pasta_internet_facing'], 
                    sensitive_data=st.session_state['pasta_sensitive_data'], 
                    pam=st.session_state['pasta_pam'], 
                    app_input=st.session_state['pasta_app_input']
                )

                # Show a spinner while generating the threat model
                with st.spinner("Analysing potential threats..."):
                    try:
                        # Check which model provider is selected from the main sidebar
                        if model_provider == "OpenAI API":
                            model_output = threat_model_obj.get_threat_model(
                                st.session_state['openai_api_key'], 
                                selected_model, 
                                threat_model_prompt
                            )
                        
                        # Access the threat model and improvement suggestions from the parsed content
                        threat_model = model_output.get("threat_model", [])
                        improvement_suggestions = model_output.get("improvement_suggestions", [])

                        # Convert the threat model JSON to Markdown
                        markdown_output = markdown_obj.json_to_markdown(threat_model, improvement_suggestions)

                        # Store the output in session state
                        st.session_state['pasta_threat_model_output'] = markdown_output

                        # Display the threat model in Markdown
                        st.markdown(markdown_output)

                        # Add a button to allow the user to download the output as a Markdown file
                        st.download_button(
                            label="Download Threat Model",
                            data=markdown_output,
                            file_name="pasta_gpt_threat_model.md",
                            mime="text/markdown",
                        )

                    except Exception as e:
                        st.error(f"Error generating threat model: {e}")

    # Security Controls Sub-Tab
    with pasta_tab2:
        # Display previously generated control matrix if exists
        if st.session_state['pasta_control_matrix_output']:
            st.markdown(st.session_state['pasta_control_matrix_output'])
            st.download_button(
                label="Download Control Matrix",
                data=st.session_state['pasta_control_matrix_output'],
                file_name="control_matrix_model.md",
                mime="text/markdown",
            )

        if st.button("Generate Security Controls", key="pasta_control_matrix_btn"):
            if not st.session_state['pasta_app_input']:
                st.error("Please enter your application details before submitting.")
            else:
                # Generate the prompt using the create_prompt function
                control_matrix_prompt = control_matrix_obj.create_control_matrix_prompt(
                    app_type=st.session_state['pasta_app_type'], 
                    authentication=st.session_state['pasta_authentication'], 
                    internet_facing=st.session_state['pasta_internet_facing'], 
                    sensitive_data=st.session_state['pasta_sensitive_data'], 
                    pam=st.session_state['pasta_pam'], 
                    app_input=st.session_state['pasta_app_input']
                )

                # Show a spinner while generating the control matrix
                with st.spinner("Preparing security controls..."):
                    try:
                        # Check which model provider is selected from the main sidebar
                        if model_provider == "OpenAI API":
                            model_output = control_matrix_obj.get_control_matrix(
                                st.session_state['openai_api_key'], 
                                selected_model, 
                                control_matrix_prompt
                            )
                        
                        # Access the control matrix and improvement suggestions from the parsed content
                        control_matrix = model_output.get("control_matrix", [])
                        improvement_suggestions = model_output.get("improvement_suggestions", [])

                        # Convert the control matrix JSON to Markdown
                        markdown_output = markdown_obj.json_to_markdown_control(control_matrix, improvement_suggestions)

                        # Store the output in session state
                        st.session_state['pasta_control_matrix_output'] = markdown_output

                        # Display the control matrix in Markdown
                        st.markdown(markdown_output)

                        # Add a button to allow the user to download the output as a Markdown file
                        st.download_button(
                            label="Download Control Matrix",
                            data=markdown_output,
                            file_name="control_matrix_model.md",
                            mime="text/markdown",
                        )

                    except Exception as e:
                        st.error(f"Error generating control matrix: {e}")

    # MITRE Attack Tree Sub-Tab
    with pasta_tab3:
        # Display previously generated attack tree if exists
        if st.session_state['pasta_attack_tree_output']:
            st.write("Attack Tree Code:")
            st.code(st.session_state['pasta_attack_tree_output'])
            st.write("Attack Tree Diagram Preview:")
            attack_tree_obj.mermaid(st.session_state['pasta_attack_tree_output'])
            
            col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
            
            with col1:              
                # Add a button to allow the user to download the Mermaid code
                st.download_button(
                    label="Download Diagram Code",
                    data=st.session_state['pasta_attack_tree_output'],
                    file_name="attack_tree.md",
                    mime="text/plain",
                    help="Download the Mermaid code for the attack tree diagram."
                )

            with col2:
                # Add a button to allow the user to open the Mermaid Live editor
                mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")

        if st.button("Generate MITRE Attack Tree", key="pasta_attack_tree_btn"):
            if not st.session_state['pasta_app_input']:
                st.error("Please enter your application details before submitting.")
            else:
                # Generate the prompt using the create_attack_tree_prompt function
                attack_tree_prompt = attack_tree_obj.create_attack_tree_prompt(
                    app_type=st.session_state['pasta_app_type'], 
                    authentication=st.session_state['pasta_authentication'], 
                    internet_facing=st.session_state['pasta_internet_facing'], 
                    sensitive_data=st.session_state['pasta_sensitive_data'], 
                    pam=st.session_state['pasta_pam'], 
                    app_input=st.session_state['pasta_app_input']
                )

                # Show a spinner while generating the attack tree
                with st.spinner("Generating attack tree..."):
                    try:
                        # Check which model provider is selected from the main sidebar
                        if model_provider == "OpenAI API":
                            mermaid_code = attack_tree_obj.get_attack_tree(
                                st.session_state['openai_api_key'], 
                                selected_model, 
                                attack_tree_prompt
                            )

                        # Store the output in session state
                        st.session_state['pasta_attack_tree_output'] = mermaid_code

                        # Display the generated attack tree code
                        st.write("Attack Tree Code:")
                        st.code(mermaid_code)

                        # Visualise the attack tree using the Mermaid custom component
                        st.write("Attack Tree Diagram Preview:")
                        attack_tree_obj.mermaid(mermaid_code)
                        
                        col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                        
                        with col1:              
                            # Add a button to allow the user to download the Mermaid code
                            st.download_button(
                                label="Download Diagram Code",
                                data=mermaid_code,
                                file_name="attack_tree.md",
                                mime="text/plain",
                                help="Download the Mermaid code for the attack tree diagram."
                            )

                        with col2:
                            # Add a button to allow the user to open the Mermaid Live editor
                            mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")
                        
                    except Exception as e:
                        st.error(f"Error generating attack tree: {e}")