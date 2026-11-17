# Dream Villa - Private Resort Booking System

## Project Description

Dream Villa is a private resort booking website developed using Python Flask, MySQL, HTML, CSS, Bootstrap, and JavaScript.

The system allows customers to view resort information, check availability, make reservations, and submit payment references. Administrators can manage bookings, verify payments, and manage unavailable dates.

## Technologies Used

- Python
- Flask
- MySQL
- HTML
- CSS
- Bootstrap
- JavaScript

## Requirements

- Python installed
- MySQL Server
- Visual Studio Code (recommended)
- Git

## Installation and Setup

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_LINK
```

### 2. Open the Project Folder

```bash
cd Dream-Villa
```

### 3. Create a Virtual Environment

```bash
python3 -m venv venv
```

Activate it:

**Mac/Linux:**
```bash
source venv/bin/activate
```

**Windows:**
```bash
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Initialize the Database

1. Open MySQL Workbench or phpMyAdmin.
2. Create a database named `dream_villa`.
3. Import and execute `database/dream_villa.sql`.
4. Make sure the database connection settings in `website.py` match your local MySQL configuration.

**Note:** The included SQL file contains the database structure only. It does not contain actual customer bookings or account records.

### 6. Configure Environment Variables

Create a `.env` file in the main project folder, beside `website.py`.

Add the required environment variables:

```env
SECRET_KEY=your_secret_key
DREAM_VILLA_EMAIL=your_gmail_address
DREAM_VILLA_EMAIL_APP_PASSWORD=your_gmail_app_password
```

Replace the example values with your own credentials.

**Important:** Never upload your `.env` file, email credentials, or private customer information to GitHub.

### 7. Run the Application

```bash
python3 website.py
```

### 8. Open the Website

Open your browser and visit:

http://127.0.0.1:5001

## Main Features

- Customer Registration and Login
- Secure Password Hashing
- Password Reset through Email
- Resort Rooms and Amenities
- Online Booking and Reservation
- Booking Availability Checking
- GCash Payment Reference Submission
- Payment Receipt Upload
- Customer Dashboard
- Admin Dashboard
- Booking and Payment Management
- Unavailable Date Management

## Developer

Dream Villa - Private Resort Booking System