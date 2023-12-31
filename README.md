# QRCody - Flask QR Code Generator Web App

QRCody is a Flask-based web application that allows users to generate QR codes for custom text or URLs. It provides an intuitive and user-friendly interface for both anonymous and authenticated users. The app offers the following key features:

## Features:

1. **QR Code Generation**: Users can generate QR codes with custom text or URLs.

2. **Daily Limit for Anonymous Users**: Anonymous users can generate up to 5 QR codes per day.

3. **User Authentication**: Users can sign up and log in to the web app.

4. **Unlimited QR Codes for Authenticated Users**: Authenticated users have the privilege to generate an unlimited number of QR codes.

5. **QR Code Download**: Users can download the generated QR codes as image files.

## Installation:

To run the QRCody web app locally, follow these steps:

1. Clone the repository to your local machine.
2. Create a virtual environment (optional but recommended).
3. Install the required dependencies using `pip install -r requirements.txt`.
4. Set up the database and tables required for user authentication and data storage.
5. Set the `secret_key` for session management in `app.py`.
6. Run the Flask app with `python app.py`.
7. Access the web app in your browser at `http://localhost:5000`.

## Dependencies:

The QRCody web app relies on the following major dependencies:

- Flask: A micro web framework for Python.
- Pillow: Python Imaging Library for image processing.
- qrcode: A library to generate QR codes.

Please refer to the `requirements.txt` file for a complete list of dependencies.

Enjoy using QRCody and have fun generating QR codes with ease!
