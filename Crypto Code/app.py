from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from PIL import Image
import hashlib

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/about')
def about():
    return render_template('about.html')


def calculate_hash(file_path):
    """Calculate hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.digest()


def encrypt_hash_with_image(hash_bytes, image_path):
    """Encrypt hash with image."""
    with open(image_path, 'rb') as img_file:
        img_bytes = img_file.read()
    encrypted_bytes = bytes(h1 ^ h2 for h1, h2 in zip(hash_bytes, img_bytes))
    return encrypted_bytes


def decrypt_hash_with_image(encrypted_bytes, image_path):
    """Decrypt hash using image."""
    with open(image_path, 'rb') as img_file:
        img_bytes = img_file.read()
    decrypted_bytes = bytes(h1 ^ h2 for h1, h2 in zip(encrypted_bytes, img_bytes))
    return decrypted_bytes


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/sign', methods=['GET', 'POST'])
def sign():
    if request.method == 'POST':
        document = request.files['document']
        image = request.files['image']
        
        # Ensure the 'uploads' directory exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        # Save the document and image
        document_filename = secure_filename(document.filename)
        document_path = os.path.join(app.config['UPLOAD_FOLDER'], document_filename)
        document.save(document_path)
        image_filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        image.save(image_path)

        # Calculate document hash
        document_hash = calculate_hash(document_path)

        # Encrypt document hash with image
        encrypted_hash = encrypt_hash_with_image(document_hash, image_path)

        # Save encrypted hash as signature
        signature_filename = document_filename + '.sig'
        signature_path = os.path.join(app.config['UPLOAD_FOLDER'], signature_filename)
        with open(signature_path, 'wb') as sig_file:
            sig_file.write(encrypted_hash)

        flash('Document signed successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('sign.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        provided_document = request.files['document']
        provided_image = request.files['image']

        # Save the provided document and image
        provided_document_filename = secure_filename(provided_document.filename)
        provided_document_path = os.path.join(app.config['UPLOAD_FOLDER'], provided_document_filename)
        provided_document.save(provided_document_path)
        provided_image_filename = secure_filename(provided_image.filename)
        provided_image_path = os.path.join(app.config['UPLOAD_FOLDER'], provided_image_filename)
        provided_image.save(provided_image_path)

        # Calculate hash of provided document
        provided_document_hash = calculate_hash(provided_document_path)

        # Decrypt hash with provided image
        signature_filename = provided_document_filename + '.sig'
        signature_path = os.path.join(app.config['UPLOAD_FOLDER'], signature_filename)
        encrypted_hash = open(signature_path, 'rb').read()
        decrypted_hash = decrypt_hash_with_image(encrypted_hash, provided_image_path)

        # Compare hashes
        if decrypted_hash == provided_document_hash:
            flash('Document verified successfully!', 'success')
        else:
            flash('Document verification failed!', 'error')

        # Delete temporary files
        os.remove(provided_document_path)
        os.remove(provided_image_path)

        return redirect(url_for('index'))

    return render_template('verify.html')


if __name__ == "__main__":
    app.run(debug=True)
