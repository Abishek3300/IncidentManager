from flask import Flask, render_template_string, request
from PIL import Image, ImageFilter
import io, math, time

app = Flask(__name__)

# Sample products
PRODUCTS = [
    {"id": 1, "name": "Laptop", "price": 800},
    {"id": 2, "name": "Smartphone", "price": 500},
    {"id": 3, "name": "Headphones", "price": 150},
    {"id": 4, "name": "Smartwatch", "price": 200},
    {"id": 5, "name": "Camera", "price": 450},
]

# HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ShopEasy CPU Intensive</title>
</head>
<body>
    <h1>Welcome to ShopEasy!</h1>
    <h2>Product Catalog</h2>
    <ul>
    {% for product in products %}
        <li>{{ product.name }} - ${{ product.price }}</li>
    {% endfor %}
    </ul>
    <p>Click below to apply CPU-intensive image filters:</p>
    <form action="/process_images">
        <button type="submit">Process Product Images</button>
    </form>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE, products=PRODUCTS)

@app.route("/process_images")
def process_images():
    start_time = time.time()
    results = []
    # Simulate CPU-heavy image processing
    for i in range(40):  # 50 fake images
        img = Image.new("RGB", (1400, 1400), (i*3 % 255, i*5 % 255, i*7 % 255))
        img = img.filter(ImageFilter.GaussianBlur(radius=5))
        img = img.filter(ImageFilter.CONTOUR)
        # simulate some math per image
        _ = sum([math.sqrt(j*j) for j in range(100_000)])
        results.append(f"Image {i+1} processed")
        time.sleep(0.01)  # small sleep to avoid freezing t2.micro
    elapsed = time.time() - start_time
    return f"Processed {len(results)} product images in {elapsed:.2f}s"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)