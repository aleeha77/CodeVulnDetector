import streamlit as st
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re


@st.cache_resource
def load_security_model():
    model_name = "mrm8488/codebert-base-finetuned-detect-insecure-code"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    return tokenizer, model.to('cpu').eval()

tokenizer, model = load_security_model()


st.set_page_config(page_title="Code Guardian", layout="wide")
st.title("🔍 Real-Time Code Vulnerability Scanner")


with st.sidebar:
    st.header("Settings")
    threshold = st.slider("Detection Sensitivity", 0.0, 1.0, 0.3, 0.05)


code_input = st.text_area("Paste your code here:", height=400,
                         placeholder="// Paste code to analyze\n#include <stdio.h>\n...")

safe_patterns = [
    r'^\s*print\(.*\)\s*$',   
    r'^\s*#.*$',              
    r'^\s*$',                 
    r'^\s*\w+\s*=\s*(int|str|float)?\s*\(?input\(.*\)\)?\s*$',  
]

def is_safe_line(line):
    return any(re.match(pattern, line.strip()) for pattern in safe_patterns)

def contains_dangerous_function(line):
    dangerous_funcs = ['eval(', 'exec(', 'os.system(', 'subprocess', 'popen(']
    line_lower = line.lower()
    return any(func in line_lower for func in dangerous_funcs)


def get_suggestion(line):
    if "eval(" in line:
        return "Avoid using eval(); it's a major security risk."
    elif "exec(" in line:
        return "Avoid using exec(); it can execute arbitrary code."
    elif "os.system(" in line:
        return "Avoid os.system(); consider using subprocess.run with proper sanitization."
    elif "input(" in line:
        return "Always validate and sanitize user inputs."
    else:
        return "Potential unsafe practice detected."


if st.button("Scan Code") and code_input:
    lines = code_input.strip().split('\n')

    with st.spinner("Analyzing code..."):
        for idx, line in enumerate(lines):
            if not line.strip():
                continue

            st.markdown(f"**Line {idx+1}**")
            st.code(line, language="python")

            danger_flag = contains_dangerous_function(line)
            safe_flag = is_safe_line(line)

        
            if danger_flag:
                st.warning("⚠️ Security Warning: Dangerous function usage detected.")
                st.metric("Risk Score", "95%", delta="VULNERABLE", delta_color="inverse")
                st.warning(f"⚠️ Security Warning: {get_suggestion(line)}")
                st.divider()
                continue

            
            if safe_flag:
                st.info("✅ Line is safe (whitelisted).")
                st.metric("Risk Score", "0%", delta="SAFE", delta_color="normal")
                st.success("No significant issues detected.")
                st.divider()
                continue

            
            inputs = tokenizer(line, return_tensors="pt", truncation=True, max_length=512).to('cpu')
            with torch.no_grad():
                outputs = model(**inputs)
            vuln_prob = torch.nn.functional.softmax(outputs.logits, dim=1)[0][1].item()

            col1, col2 = st.columns([0.2, 0.8])
            with col1:
                status = "VULNERABLE" if vuln_prob > threshold else "SAFE"
                st.metric("Risk Score", f"{vuln_prob:.0%}", delta=status, delta_color="inverse")

            with col2:
                if vuln_prob > threshold:
                    st.warning(f"⚠️ Security Warning: {get_suggestion(line)}")
                else:
                    st.success("No significant issues detected.")

            st.divider()
