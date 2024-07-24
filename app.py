# imports
import csv
import os
import io
from google.cloud.vision_v1 import ImageAnnotatorClient, Feature
from flask import Flask, request, jsonify, render_template, flash, session, redirect, url_for
from werkzeug.utils import secure_filename
from google.cloud import vision, storage
from google.cloud.vision_v1 import ImageAnnotatorClient
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import logging
import pandas as pd
from sklearn.metrics import jaccard_score
from sklearn.preprocessing import MultiLabelBinarizer
from io import StringIO
from flask_cors import CORS

load_dotenv()
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = os.getenv('API_KEY')

# google bucket credentials and connection
client = ImageAnnotatorClient()
# storage_client = storage.Client()
# bucket_name = 'vision-products'
# bucket = storage_client.bucket(bucket_name)
storage_client = storage.Client()
bucket = storage_client.bucket('vision-products')

# flask app
app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
logging.basicConfig(level=logging.INFO)

UPLOAD_FOLDER = r'D:\vision_app\static\uploads'

# authentication user and admin models


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')

    def chk_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')

    def chk_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


# creating all the database
with app.app_context():
    db.create_all()


@app.route('/')
def root():
    return render_template('homepage.html')

# admin resgistration


@app.route('/admin_reg', methods=['POST', 'GET'])
def admin_reg():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        admin = Admin.query.filter_by(email=email).first()
        if admin:
            flash('Email address already exists')
            return redirect(url_for('root'))

        new_admin = Admin(email=email, password=password, name=name)
        db.session.add(new_admin)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('admin_reg.html')

# admin login


@app.route('/admin_login', methods=['POST', 'GET'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        admin = Admin.query.filter_by(email=email).first()
        if admin and admin.chk_password(password):
            session.clear()  # Clear existing session
            session['admin_email'] = email  # Set session for admin
            flash('Admin Login successful!')
            # Redirect to admin_dashboard
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Admin Login failed. Check your email and password.')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


# admin dashboard
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin_email' in session:
        if request.method == 'POST':
            image_url = request.form['image_url']
            similar_images = find_similar_image(image_url, threshold=0.5)
            return render_template('admin_dashboard.html', similar_images=similar_images)
        return render_template('admin_dashboard.html')
    else:
        flash('Unauthorized access. Please log in as admin.')
        return redirect(url_for('admin_login'))


# user registration
@app.route('/user_reg', methods=['POST', 'GET'])
def user_reg():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('root'))

        new_user = User(email=email, password=password, name=name)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('user_dashboard'))
    else:
        return render_template('user_reg.html')


# user login
@app.route('/user_login', methods=['POST', 'GET'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.chk_password(password):
            session.clear()  # Clear existing session
            session['user_email'] = email  # Set session for user
            flash('User Login successful!')
            return redirect(url_for('user_dashboard'))
        else:
            flash('User Login failed. Check your email and password.')
            return redirect(url_for('user_login'))

    return render_template('user_login.html')


# user dashboard
@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_email' in session:
        if request.method == 'POST':
            image_url = request.form['image_url']
            # Assuming find_similar_image is a function defined elsewhere
            similar_images = find_similar_image(image_url, threshold=0.5)
            return render_template('user_dashboard.html', similar_images=similar_images)
        return render_template('user_dashboard.html')
    else:
        flash('Unauthorized access. Please log in as user.')
        return redirect(url_for('user_login'))


# detect features of image url
def detect_features(image_path_or_url):
    try:
        if image_path_or_url.startswith('http://') or image_path_or_url.startswith('https://'):
            image = vision.Image()
            image.source.image_uri = image_path_or_url
        else:
            with io.open(image_path_or_url, 'rb') as image_file:
                content = image_file.read()
            image = vision.Image(content=content)

        response = client.annotate_image({
            'image': image,
            'features': [
                Feature(type_=Feature.Type.LABEL_DETECTION),
                Feature(type_=Feature.Type.TEXT_DETECTION),
                Feature(type_=Feature.Type.LOGO_DETECTION),
                Feature(type_=Feature.Type.OBJECT_LOCALIZATION),
            ],
        })

        return {
            'labels': [label.description for label in response.label_annotations],
            'texts': [text.description for text in response.text_annotations],
            'logos': [logo.description for logo in response.logo_annotations],
            'objects': [obj.name for obj in response.localized_object_annotations],
        }
    except Exception as e:
        logging.error(f"Error detecting features: {e}")
        return {
            'labels': [],
            'texts': [],
            'logos': [],
            'objects': [],
        }

 # detect features of image


def detect_feature_images(image_path):
    features = {
        'labels': [],
        # 'texts': [],
        # 'logos': [],
        # 'objects': []
    }

    with open(image_path, 'rb') as image_file:
        content = image_file.read()
        image = vision.Image(content=content)

        response = client.label_detection(image=image)
        features['labels'] = [
            label.description for label in response.label_annotations]

        # response = client.text_detection(image=image)
        # features['texts'] = [
        #     text.description for text in response.text_annotations]

        # response = client.logo_detection(image=image)
        # features['logos'] = [
        #     logo.description for logo in response.logo_annotations]

        # response = client.object_localization(image=image)
        # features['objects'] = [
        #     obj.name for obj in response.localized_object_annotations]
    # print(features)
    return features


def jaccard_similarity(set1, set2):
    intersection = len(set1 & set2)
    # print("i:",intersection)
    union = len(set1 | set2)
    # print("u:",union)
    return intersection / union if union != 0 else 0


# to find relevant searches
def find_similar_image(input_image_path_or_url, threshold=0.5):
    input_features = detect_features(input_image_path_or_url)
    input_labels = set(input_features['labels'])
    input_texts = set(input_features['texts'])
    input_logos = set(input_features['logos'])
    input_objects = set(input_features['objects'])
    similar_images = []

    try:
        products = read_csv_from_bucket()
        for product in products:
            description = product['description']
            try:
                description_labels = set(description.split('Labels: ')[
                                         1].split('Texts: ')[0].strip(', ').split(', '))
                description_texts = set(description.split('Texts: ')[
                                        1].split('Logos: ')[0].strip(', ').split(', '))
                description_logos = set(description.split('Logos: ')[1].split(
                    'Objects: ')[0].strip(', ').split(', '))
                description_objects = set(description.split(
                    'Objects: ')[1].strip(', ').split(', '))
            except IndexError:
                continue

            similarities = [
                jaccard_similarity(input_labels, description_labels),
                jaccard_similarity(input_texts, description_texts),
                jaccard_similarity(input_logos, description_logos),
                jaccard_similarity(input_objects, description_objects)
            ]
            print("sim:  ", similarities)
            if any(sim >= threshold for sim in similarities):
                similar_images.append(
                    {'product-name': product['product-name'], 'url': product['url']})
    except Exception as e:
        logging.error(f"Error finding similar images: {e}")

    return similar_images


# by image upload relevant search
def find_similar_image_by_image(input_image_path, threshold=0.5):
    input_features = detect_feature_images(input_image_path)
    input_labels = set(input_features['labels'])
    print("in: ", input_labels)
    # input_texts = set(input_features['texts'])
    # input_logos = set(input_features['logos'])
    # input_objects = set(input_features['objects'])
    similar_images = []

    try:
        products = read_csv_from_bucket()
        for product in products:
            description = product['description']
            try:
                description_labels = set(description.split('Labels: ')[
                                         1].split('Texts: ')[0].strip(', ').split(', '))
                print("DB: ", description_labels)
                # description_texts = set(description.split('Texts: ')[
                #                         1].split('Logos: ')[0].strip(', ').split(', '))
                # description_logos = set(description.split('Logos: ')[1].split(
                #     'Objects: ')[0].strip(', ').split(', '))
                # description_objects = set(description.split(
                #     'Objects: ')[1].strip(', ').split(', '))
            except IndexError:
                continue

            similarities = [
                jaccard_similarity(input_labels, description_labels),
                # jaccard_similarity(input_texts, description_texts),
                # jaccard_similarity(input_logos, description_logos),
                # jaccard_similarity(input_objects, description_objects)
            ]

            # simm = (similarities[0]+similarities[1])/2
            # print("sim:  ",similarities)
            # print(simm)

            if any(sim >= threshold for sim in similarities):
                similar_images.append(
                    {'product-name': product['product-name'], 'url': product['url'], 'sim': similarities[0]})

    except Exception as e:
        logging.error(f"Error finding similar images: {e}")

    return similar_images

# search product by name


@app.route('/api/search_product', methods=['POST', 'GET'])
def search_product():
    product_name = request.json.get('product-name')
    if not product_name:
        return jsonify({'error': 'Product name is required'}), 400
    try:
        # Read products from the bucket
        products = read_csv_from_bucket()

        similar_products = []
        for product in products:
            if product_name.lower() in product['product-name'].lower():
                similar_products.append({
                    'product-name': product['product-name'],
                    'image-url': product['url']
                })
        return jsonify(similar_products)
    except Exception as e:
        logging.error(f"Error searching products: {str(e)}")
        return jsonify({'error': str(e)}), 500


# read and write function of csv from bucket
def read_csv_from_bucket():
    blob = bucket.blob('results.csv')
    try:
        logging.info('Attempting to download CSV from bucket.')
        # Explicitly reload the blob before downloading
        blob.reload()
        data = blob.download_as_string().decode('utf-8')
        logging.info(f'Successfully downloaded CSV from bucket. Size: {
                     len(data)} bytes')
        products = list(csv.DictReader(io.StringIO(data)))
        logging.info(f'Number of products read: {len(products)}')
        return products
    except Exception as e:
        logging.error(f"Error reading CSV from bucket: {str(e)}")
        return []


def write_csv_to_bucket(products):
    blob = bucket.blob('results.csv')
    output = io.StringIO()
    writer = csv.DictWriter(
        output, fieldnames=['product-name', 'url', 'description'])
    writer.writeheader()
    writer.writerows(products)
    try:
        logging.info('Attempting to upload CSV to bucket.')
        blob.upload_from_string(output.getvalue(), content_type='text/csv')
        logging.info(f'Successfully uploaded CSV to bucket. Content: {
                     output.getvalue()}')

        blob.reload()
        logging.info(f'Blob size after upload: {blob.size} bytes')
    except Exception as e:
        logging.error(f"Error uploading CSV to bucket: {str(e)}")
        raise

# routes for operations - add product


@app.route('/api/add_product', methods=['POST'])
def add_product():
    data = request.json
    product_name = data.get('product-name')
    url = data.get('url')

    if not product_name or not url:
        return jsonify({'error': 'product-name and url are required'}), 400

    try:
        features = detect_features(url)
        description = f"Labels: {', '.join(features['labels'])}, Texts: {', '.join(features['texts'])}, Logos: {
            ', '.join(features['logos'])}, Objects: {', '.join(features['objects'])}"

        existing_products = read_csv_from_bucket()
        logging.info(f"Number of existing products: {len(existing_products)}")

        if any(product['product-name'] == product_name for product in existing_products):
            return jsonify({'error': 'Product already exists'}), 400

        new_product = {
            'product-name': product_name,
            'url': url,
            'description': description
        }
        existing_products.append(new_product)

        write_csv_to_bucket(existing_products)

        updated_products = read_csv_from_bucket()
        logging.info(f"Number of products after addition: {
                     len(updated_products)}")

        if any(product['product-name'] == product_name for product in updated_products):
            return jsonify({'message': 'Product added successfully'}), 201
        else:
            return jsonify({'error': 'Product was not successfully added'}), 500

    except Exception as e:
        logging.error(f"Error adding product: {str(e)}")
        return jsonify({'error': str(e)}), 500

# add processed csv file into bucket


@app.route('/api/merge_csv', methods=['POST'])
def merge_csv():
    file = request.files.get('file')

    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    try:
        file_content = file.stream.read().decode('utf-8')
        file.stream.seek(0)

        reader = csv.reader(io.StringIO(file_content))
        headers = next(reader, None)
        if headers != ['product-name', 'url']:
            return jsonify({'error': 'Uploaded CSV is invalid. Expected headers: product-name, url'}), 400

        new_products = [{'product-name': row[0], 'url': row[1]}
                        for row in reader if len(row) == 2]
        logging.info(f"New products to be added: {new_products}")

        # Read existing products from bucket
        existing_products = read_csv_from_bucket()
        logging.info(f"Existing products: {existing_products}")

        existing_product_set = set(
            (product['product-name'], product['url']) for product in existing_products)

        products_to_add = []
        for new_product in new_products:
            if (new_product['product-name'], new_product['url']) not in existing_product_set:
                features = detect_features(new_product['url'])
                description = f"Labels: {', '.join(features['labels'])}, Texts: {', '.join(features['texts'])}, Logos: {
                    ', '.join(features['logos'])}, Objects: {', '.join(features['objects'])}"
                new_product['description'] = description
                products_to_add.append(new_product)
            else:
                logging.info(f"Duplicate product found: {new_product}")

        existing_products.extend(products_to_add)
        logging.info(f"Final products to be uploaded: {existing_products}")

        write_csv_to_bucket(existing_products)

        return jsonify({'message': 'CSV files merged successfully'}), 200
    except Exception as e:
        logging.error(f"Error merging CSV files: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/get_products', methods=['GET'])
def get_products():
    try:
        products = read_csv_from_bucket()
        clean_products = []
        for product in products:
            clean_product = {key: (value if value is not None else '')
                             for key, value in product.items()}
            clean_products.append(clean_product)
        return jsonify(clean_products), 200
    except Exception as e:
        logging.error(f"Error reading products from bucket: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/products', methods=['GET'])
def display_products():
    try:
        products = read_csv_from_bucket()
        clean_products = []
        for product in products:
            clean_product = {key: (value if value is not None else '')
                             for key, value in product.items()}
            clean_products.append(clean_product)
            print(len(clean_products))
        return render_template('products.html', products=clean_products)
    except Exception as e:
        logging.error(f"Error reading products from bucket: {str(e)}")
        return render_template('error.html', error=str(e)), 500


@app.route('/api/initial_products', methods=['GET'])
def get_initial_products():
    try:
        products = read_csv_from_bucket()
        clean_products = []
        for product in products[:15]:  # Limit to first 15 products
            clean_product = {key: (value if value is not None else '')
                             for key, value in product.items()}
            clean_products.append(clean_product)
        return jsonify(clean_products)
    except Exception as e:
        logging.error(f"Error reading products from bucket: {str(e)}")
        return jsonify({"error": str(e)}), 500


def upload_image_and_get_path(file):
    try:
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            return file_path
        return None
    except Exception as e:
        logging.error(f"Error saving uploaded image: {str(e)}")
        return None


def handle_uploaded_image(file):
    local_path = upload_image_and_get_path(file)
    if not local_path:
        return []
    similar_images = find_similar_image(local_path, threshold=0.1)
    return similar_images


@app.route('/api/upload_image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        try:
            local_path = upload_image_and_get_path(file)
            if not local_path:
                return jsonify({'error': 'Failed to save uploaded image'}), 500

            similar_products = find_similar_image_by_image(local_path)
            sorted_similarity = sorted(
                similar_products, key=lambda x: x['sim'], reverse=True)

            return jsonify(sorted_similarity)
        except Exception as e:
            logging.error(f"Error processing uploaded image: {str(e)}")
            return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=5000, debug=True)
