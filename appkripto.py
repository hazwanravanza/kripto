import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from algorithm import *

app = Flask(__name__)
app.secret_key = 'hazwanravanza'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

@app.route('/')
def index():   
    return render_template('index.html')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/upload-file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})
    
    file = request.files['file']
    key = request.form.get('key')
    action = request.form['action']
    algorithm = request.form['algorithm']

    if algorithm == 'DES' or algorithm == 'AES':
        mode = request.form['mode']

    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
    
    if file:
        if action == 'encrypt':
            filename = 'Encrypted_' + secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            if algorithm == 'XOR':
                xor_cipher_encrypt(file, file_path, key)
            elif algorithm == 'RC4':
                RC4_encrypt(file, file_path, key)
            elif algorithm == 'DES':
                DES_encrypt(file, file_path, key, mode)
            elif algorithm == 'AES':
                AES_encrypt(file, file_path, key, mode)

            return jsonify({
                'success': True,
                'filename': filename,
                }), 200

        elif action == 'decrypt':
            filename = 'Decrypted_' + secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            if algorithm == 'XOR':
                xor_cipher_decrypt(file, file_path, key)
            elif algorithm == 'RC4':
                RC4_decrypt(file, file_path, key)
            elif algorithm == 'DES':
                DES_decrypt(file, file_path, key, mode)
            elif algorithm == 'AES':
                AES_decrypt(file, file_path, key, mode)

            return jsonify({
                'success': True,
                'filename': filename,
                }), 200 
        
    return jsonify({'error': 'Invalid file type'}), 400
   
@app.route('/upload-text', methods=['POST'])
def upload_text():
    text = request.form.get('text1')
    key = request.form.get('key1')
    action = request.form['action']
    algorithm = request.form['algorithm1']

    if algorithm == 'DES' or algorithm == 'AES':
        mode1 = request.form['mode1']
    
    if text:
        if action == 'encrypt1':
            if algorithm == 'XOR':
                resultteks = xor_encrypt_decrypt(text, key)
            elif algorithm == 'RC4':
                resultteks = RC4_encrypt1(text, key)
            elif algorithm == 'DES':
                resultteks = DES_encrypt1(text, key, mode1)
            elif algorithm == 'AES':
                resultteks = AES_encrypt1(text, key, mode1)

            return jsonify({
                'success': True,
                'resultteks': resultteks
                }), 200

        elif action == 'decrypt1':
            if algorithm == 'XOR':
                resultteks = xor_encrypt_decrypt(text, key)
            elif algorithm == 'RC4':
                resultteks = RC4_decrypt1(text, key)
            elif algorithm == 'DES':
                resultteks = DES_decrypt1(text, key, mode1)
            elif algorithm == 'AES':
                resultteks = AES_decrypt1(text, key, mode1)

            return jsonify({
                'success': True,
                'resultteks': resultteks
                }), 200 
        
    return jsonify({'error': 'Invalid file type'}), 400

if __name__ == "__main__":
    app.run(debug=True)