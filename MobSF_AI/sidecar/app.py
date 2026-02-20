from flask import Flask, render_template, request, jsonify
import requests
import os
from openai import OpenAI
import json

app = Flask(__name__)

MOBSF_URL = os.environ.get('MOBSF_URL', 'http://mobsf:8000')
MOBSF_API_KEY = os.environ.get('MOBSF_API_KEY', '')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')

client = OpenAI(api_key=OPENAI_API_KEY)

@app.route('/chat/<scan_hash>/')
def chat_ui(scan_hash):
    # We can pass scan_hash to the template
    return render_template('chat.html', scan_hash=scan_hash)

@app.route('/api/chat', methods=['POST'])
def chat_api():
    data = request.json
    scan_hash = data.get('hash')
    message = data.get('message')
    history = data.get('history', [])

    if not scan_hash or not message:
        return jsonify({'error': 'Missing hash or message'}), 400

    headers = {'Authorization': MOBSF_API_KEY}
    try:
        # Fetch report from MobSF
        resp = requests.post(f"{MOBSF_URL}/api/v1/report_json", data={'hash': scan_hash}, headers=headers)
        if resp.status_code != 200:
             return jsonify({'error': f"MobSF Error: {resp.status_code} {resp.text}"}), 500
        
        report_data = resp.json()
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    system_instruction = f"""
    You are a security analyst assistant for MobSF.
    Report Context:
    {json.dumps(report_data, default=str)[:50000]}
    
    Answer the user's question based on this report.
    """
    
    messages = [{"role": "system", "content": system_instruction}]
    for turn in history:
        # Gemini format adaptation if needed, but sidecar uses new format
        role = turn.get('role', 'user')
        if role == 'model':
            role = 'assistant'
            
        content = turn.get('content', '')
        if not content and 'parts' in turn:
             content = turn['parts'][0]
        messages.append({"role": role, "content": str(content)})
    
    messages.append({"role": "user", "content": message})

    try:
        completion = client.chat.completions.create(
            model="gpt-4o",
            messages=messages
        )
        reply = completion.choices[0].message.content
        return jsonify({'response': reply})
    except Exception as e:
         return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
