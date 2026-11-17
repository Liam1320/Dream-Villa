
from dotenv import load_dotenv

load_dotenv()
import os
import re
import uuid
import csv
import secrets
import hashlib
import hmac
import smtplib
import time as time_module
from email.message import EmailMessage
from email.utils import parseaddr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from io import StringIO
from datetime import date, datetime, timedelta, time
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session,
    send_from_directory, abort, make_response
)

from flask_wtf.csrf import CSRFProtect

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

import mysql.connector
from dotenv import load_dotenv

# Load settings from the .env file beside website.py.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


app = Flask(__name__)


def password_meets_requirements(password):
    """Require at least 8 characters, one letter, and one number."""
    return (
        len(password) >= 8
        and re.search(r"[A-Za-z]", password) is not None
        and re.search(r"[0-9]", password) is not None
    )

# ==========================================
# APPLICATION SETTINGS
# ==========================================

# Change this secret before deploying publicly.
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing. Add SECRET_KEY=your_generated_key to the .env file."
    )
app.secret_key = os.getenv("SECRET_KEY")

csrf = CSRFProtect(app)

# Maximum upload size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Private receipt storage (NOT inside static).
RECEIPT_FOLDER = os.path.join(
    app.root_path,
    "private_receipts"
)

ALLOWED_RECEIPT_EXTENSIONS = {
    "jpg", "jpeg", "png", "webp"
}

os.makedirs(RECEIPT_FOLDER, exist_ok=True)


# ==========================================
# RECEIPT VALIDATION
# ==========================================

def allowed_receipt(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_RECEIPT_EXTENSIONS
    )


def valid_image_signature(file):
    """
    Check the actual file signature.
    Do not trust the filename or browser MIME type.
    """

    file.seek(0)
    header = file.read(12)
    file.seek(0)

    is_jpeg = header.startswith(b"\xff\xd8\xff")

    is_png = header.startswith(
        b"\x89PNG\r\n\x1a\n"
    )

    is_webp = (
        header.startswith(b"RIFF")
        and header[8:12] == b"WEBP"
    )

    return is_jpeg or is_png or is_webp


def image_extension_matches(filename, file):
    extension = filename.rsplit(".", 1)[1].lower()

    file.seek(0)
    header = file.read(12)
    file.seek(0)

    if extension in ("jpg", "jpeg"):
        return header.startswith(b"\xff\xd8\xff")

    if extension == "png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")

    if extension == "webp":
        return (
            header.startswith(b"RIFF")
            and header[8:12] == b"WEBP"
        )

    return False


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="",
        database="dream_villa"
    )


# ==========================================
# ADMIN-ONLY ACCESS
# ==========================================

def admin_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in with an admin account.")
            return redirect(url_for("login"))

        if session.get("user_role") != "admin":
            flash("Access denied. Admin permission is required.")
            return redirect(url_for("dashboard"))

        return view_function(*args, **kwargs)

    return wrapped_view

# ==========================================
# ADMIN ACTIVITY LOG FUNCTION
# ==========================================

def log_admin_activity(action, details, booking_id=None):
    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        admin_id = session.get("user_id")
        admin_name = session.get("user_name", "Admin")

        cursor.execute("""
            INSERT INTO admin_activity_logs (
                admin_id,
                admin_name,
                action,
                details,
                booking_id
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            admin_id,
            admin_name,
            action,
            details,
            booking_id
        ))

        db.commit()

    except mysql.connector.Error:
        app.logger.exception("ACTIVITY LOG ERROR")

    finally:
        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()




# ==========================================
# GET UNAVAILABLE DATES
# ==========================================

def get_unavailable_dates():

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT unavailable_date
            FROM unavailable_dates
            ORDER BY unavailable_date ASC
        """)

        return [
            row[0].strftime("%Y-%m-%d")
            if hasattr(row[0], "strftime")
            else str(row[0])[:10]
            for row in cursor.fetchall()
        ]

    finally:
        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# PUBLIC WEBSITE PAGES
# ==========================================

@app.route("/rooms")
def rooms():
    return render_template("rooms.html")


@app.route("/amenities")
def amenities():
    return render_template("amenities.html")


@app.route("/virtual-tour")
def virtual_tour():
    return render_template("virtual_tour.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# ==========================================
# EMAIL OTP SETTINGS AND HELPERS
# ==========================================
OTP_LIFETIME_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 60
EMAIL_VERIFICATION_LIFETIME_SECONDS = 600

def send_booking_otp_email(recipient, customer_name, otp_code):
    """Send a booking verification code using Gmail SMTP over SSL (port 465)."""
    sender = os.environ.get("DREAM_VILLA_EMAIL", "").strip()
    app_password = os.environ.get(
        "DREAM_VILLA_EMAIL_APP_PASSWORD", ""
    ).replace(" ", "").strip()

    if not sender or not app_password:
        raise RuntimeError(
            "Gmail is not configured. Set DREAM_VILLA_EMAIL and "
            "DREAM_VILLA_EMAIL_APP_PASSWORD in the .env file."
        )

    message = EmailMessage()
    message["Subject"] = "Dream Villa - Email Verification Code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Hello {customer_name},\n\n"
        f"Your Dream Villa booking verification code is: {otp_code}\n\n"
        "This code expires in 5 minutes. Do not share it with anyone.\n\n"
        "If you did not request this code, you can ignore this email.\n\n"
        "Dream Villa"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
        smtp.login(sender, app_password)
        smtp.send_message(message)


def send_customer_notification_email(recipient, subject, body):
    """Send customer notifications using Gmail SMTP over SSL (port 465)."""
    sender = os.environ.get("DREAM_VILLA_EMAIL", "").strip()
    app_password = os.environ.get(
        "DREAM_VILLA_EMAIL_APP_PASSWORD", ""
    ).replace(" ", "").strip()

    if not sender or not app_password:
        raise RuntimeError(
            "Gmail is not configured. Set DREAM_VILLA_EMAIL and "
            "DREAM_VILLA_EMAIL_APP_PASSWORD in the .env file."
        )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
        smtp.login(sender, app_password)
        smtp.send_message(message)


def send_password_reset_email(recipient, customer_name, reset_link):
    """Send a short-lived Dream Villa password reset link."""
    sender = os.environ.get("DREAM_VILLA_EMAIL", "").strip()
    app_password = os.environ.get(
        "DREAM_VILLA_EMAIL_APP_PASSWORD", ""
    ).replace(" ", "").strip()

    if not sender or not app_password:
        raise RuntimeError("Gmail is not configured.")

    message = EmailMessage()
    message["Subject"] = "Dream Villa - Password Reset"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Hello {customer_name},\n\n"
        "We received a request to reset your Dream Villa password.\n\n"
        f"Use this link to create a new password:\n{reset_link}\n\n"
        "This link expires in 15 minutes and can only be used once.\n\n"
        "If you did not request this, you can ignore this email.\n\n"
        "Dream Villa"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
        smtp.login(sender, app_password)
        smtp.send_message(message)


def notify_customer(recipient, subject, body, context):
    """Email failures must not undo a booking or admin status change."""
    try:
        send_customer_notification_email(recipient, subject, body)
        app.logger.info("CUSTOMER EMAIL SENT: %s", context)
        return True
    except Exception:
        app.logger.exception("CUSTOMER EMAIL FAILED: %s", context)
        return False


def clear_booking_otp():
    for key in (
        "booking_otp_hash", "booking_otp_email", "booking_otp_name",
        "booking_otp_expires", "booking_otp_attempts", "booking_otp_last_sent"
    ):
        session.pop(key, None)


@app.route("/send-booking-otp", methods=["POST"])
def send_booking_otp():
    customer_name = request.form.get("name", "").strip()
    customer_email = request.form.get("email", "").strip().lower()
    parsed_name, parsed_email = parseaddr(customer_email)

    if (not customer_name or len(customer_name) > 100 or
            not customer_email or len(customer_email) > 100 or
            parsed_email != customer_email or "@" not in customer_email):
        return {"success": False, "message": "Enter your name and a valid email address."}, 400

    now = time_module.time()
    last_sent = session.get("booking_otp_last_sent", 0)
    if (session.get("booking_otp_email") == customer_email and
            now - last_sent < OTP_RESEND_SECONDS):
        wait_seconds = max(1, int(OTP_RESEND_SECONDS - (now - last_sent)))
        return {"success": False, "message": f"Please wait {wait_seconds} seconds before requesting another code."}, 429

    otp_code = f"{secrets.randbelow(1_000_000):06d}"
    clear_booking_otp()
    session.pop("booking_email_verified", None)
    session.pop("booking_verified_email", None)
    session.pop("booking_verified_name", None)

    try:
        send_booking_otp_email(customer_email, customer_name, otp_code)
    except Exception:
        app.logger.exception("BOOKING OTP EMAIL ERROR")
        return {"success": False, "message": "The verification email could not be sent. Please check the Gmail setup or try again later."}, 500

    session["booking_otp_hash"] = hashlib.sha256(otp_code.encode()).hexdigest()
    session["booking_otp_email"] = customer_email
    session["booking_otp_name"] = customer_name.casefold()
    session["booking_otp_expires"] = now + OTP_LIFETIME_SECONDS
    session["booking_otp_attempts"] = 0
    session["booking_otp_last_sent"] = now
    session.modified = True

    return {"success": True, "message": "OTP sent. Please check your inbox and spam folder."}


@app.route("/verify-booking-otp", methods=["POST"])
def verify_booking_otp():
    customer_name = request.form.get("name", "").strip()
    customer_email = request.form.get("email", "").strip().lower()
    entered_otp = request.form.get("otp", "").strip()

    if (customer_email != session.get("booking_otp_email") or
            customer_name.casefold() != session.get("booking_otp_name")):
        return {"success": False, "message": "The name or email does not match the OTP request. Please request a new code."}, 400

    if time_module.time() > session.get("booking_otp_expires", 0):
        clear_booking_otp()
        return {"success": False, "message": "Your OTP has expired. Please request a new code."}, 400

    if session.get("booking_otp_attempts", 0) >= OTP_MAX_ATTEMPTS:
        clear_booking_otp()
        return {"success": False, "message": "Too many attempts. Please request a new code."}, 429

    expected_hash = session.get("booking_otp_hash", "")
    entered_hash = hashlib.sha256(entered_otp.encode()).hexdigest()
    if len(entered_otp) != 6 or not entered_otp.isdigit() or not hmac.compare_digest(expected_hash, entered_hash):
        session["booking_otp_attempts"] = session.get("booking_otp_attempts", 0) + 1
        session.modified = True
        remaining = max(0, OTP_MAX_ATTEMPTS - session["booking_otp_attempts"])
        return {"success": False, "message": f"Incorrect OTP. Attempts remaining: {remaining}."}, 400

    session["booking_email_verified"] = True
    session["booking_verified_email"] = customer_email
    session["booking_verified_name"] = customer_name.casefold()
    session["booking_verified_expires"] = time_module.time() + EMAIL_VERIFICATION_LIFETIME_SECONDS
    clear_booking_otp()
    session.modified = True
    return {"success": True, "message": "Email verified successfully. You can now submit your booking."}


# ==========================================
# BOOKING PAGE AND SAVE BOOKING
# ==========================================

@app.route("/booking", methods=["GET", "POST"])
def booking():

    # Customers must sign in before opening the booking form.
    if "user_id" not in session:
        session["after_login"] = url_for("booking")
        flash("Please sign in first before making a reservation.")
        return redirect(url_for("login", next=url_for("booking")))

    if session.get("user_role") == "admin":
        flash("Admin accounts cannot submit customer bookings.")
        return redirect(url_for("admin"))

    def render_booking_form(form_data=None, status=200):
        """Render the form in the same request so entered values are retained."""
        try:
            dates = get_unavailable_dates()
        except mysql.connector.Error:
            app.logger.exception("Could not load booking dates")
            dates = []
            flash("Unavailable dates could not be loaded. Please try again.", "error")

        values = form_data or {}
        display_name = values.get("name", session.get("user_name", ""))
        display_email = values.get("email", session.get("user_email", "")).strip().lower()
        email_verified = (
            session.get("booking_email_verified") is True
            and session.get("booking_verified_email") == display_email
            and session.get("booking_verified_name") == display_name.strip().casefold()
            and time_module.time() <= session.get("booking_verified_expires", 0)
        )

        return render_template(
            "booking.html",
            unavailable_dates=dates,
            form_data=values,
            email_verified=email_verified
        ), status

    if request.method == "GET":
        return render_booking_form()

    # Keep every submitted field so all validation/database errors can
    # redisplay the form without making the customer enter everything again.
    form_data = {
        "name": request.form.get("name", "").strip(),
        "email": request.form.get("email", "").strip(),
        "booking_type": request.form.get("booking_type", "").strip(),
        "guests": request.form.get("guests", "").strip(),
        "add_second_room": request.form.get("add_second_room") == "yes",
        "checkin": request.form.get("checkin", "").strip(),
    }

    def show_form_error(message, status=200):
        flash(message, "error")
        return render_booking_form(form_data, status)

    db = None
    cursor = None

    try:
        name = form_data["name"]
        email = form_data["email"].lower()
        booking_type = form_data["booking_type"]
        checkin_text = form_data["checkin"]
        guests_text = form_data["guests"]

        if not all([name, email, booking_type, checkin_text, guests_text]):
            return show_form_error("Please complete all booking fields. Your entered details have been kept.")

        if len(name) > 100 or len(email) > 100:
            return show_form_error("Name or email is too long. Please correct the field and try again.")

        # Check all regular booking fields before OTP so a missed selection
        # displays the correct validation message without clearing the form.
        booking_options = {
            "Day": (4000, 10),
            "Night": (5000, 10),
            "Full day": (7000, 22)
        }

        if booking_type not in booking_options:
            return show_form_error("Please select Day, Night, or Full Day.")

        try:
            start_datetime = datetime.fromisoformat(checkin_text)
            guest_count = int(guests_text)
        except (ValueError, TypeError):
            return show_form_error("Please enter a valid check-in date and guest count.")

        if start_datetime < datetime.now():
            return show_form_error("Please choose a future check-in time.")

        if not 1 <= guest_count <= 100:
            return show_form_error("Guests must be between 1 and 100.")

        # Require a recent OTP verification bound to this exact name and email.
        if not (
            session.get("booking_email_verified") is True
            and session.get("booking_verified_email") == email
            and session.get("booking_verified_name") == name.casefold()
            and time_module.time() <= session.get("booking_verified_expires", 0)
        ):
            return show_form_error("Please verify your email address with the OTP before submitting your booking.")

        # Room 1 is always included. Room 2 is optional (+P500).
        add_second_room = form_data["add_second_room"]
        room = "Room 1 + Room 2" if add_second_room else "Room 1"
        room_fee = 500 if add_second_room else 0
        base_price, duration = booking_options[booking_type]
        price = base_price + room_fee
        end_datetime = start_datetime + timedelta(hours=duration)

        db = get_db_connection()
        cursor = db.cursor()

        # Check unavailable dates.
        last_occupied_date = end_datetime.date()
        if end_datetime.time() == time(0, 0):
            last_occupied_date -= timedelta(days=1)

        cursor.execute("""
            SELECT unavailable_date
            FROM unavailable_dates
            WHERE unavailable_date >= %s
              AND unavailable_date <= %s
            LIMIT 1
        """, (start_datetime.date(), last_occupied_date))

        unavailable = cursor.fetchone()
        if unavailable:
            unavailable_date = unavailable[0]
            if hasattr(unavailable_date, "strftime"):
                unavailable_date = unavailable_date.strftime("%B %d, %Y")
            return show_form_error(
                f"{unavailable_date} is unavailable. Please select another date. Your other details have been kept."
            )

        # Prevent overlapping reservations.
        cursor.execute("""
            SELECT id
            FROM bookings
            WHERE status IN ('Pending', 'Confirmed')
              AND checkin < %s
              AND checkout > %s
            LIMIT 1
        """, (end_datetime, start_datetime))

        if cursor.fetchone():
            return show_form_error("That time overlaps another booking. Please choose another check-in time. Your other details have been kept.")

        cursor.execute("""
            INSERT INTO bookings (
                name, email, booking_type, rate, room,
                checkin, checkout, guests, status,
                reservation_fee, payment_status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            name, email, booking_type, price, room,
            start_datetime, end_datetime, guest_count,
            "Pending", 500, "Pending"
        ))

        booking_id = cursor.lastrowid
        db.commit()

        notify_customer(
            email,
            f"Dream Villa - Booking Request Received (#{booking_id})",
            f"Hello {name},\n\n"
            f"We received your booking request.\n\n"
            f"Booking reference: #{booking_id}\n"
            f"Booking type: {booking_type}\n"
            f"Room: {room}\n"
            f"Check-in: {start_datetime.strftime('%B %d, %Y at %I:%M %p')}\n"
            f"Check-out: {end_datetime.strftime('%B %d, %Y at %I:%M %p')}\n"
            f"Guests: {guest_count}\n"
            f"Booking rate: PHP {price:,.2f}\n"
            f"Reservation fee: PHP 500.00\n\n"
            "Your reservation is currently PENDING. Please follow the payment instructions on the website. "
            "The booking is not confirmed until the admin verifies your payment and approves it.\n\n"
            "Thank you,\nDream Villa",
            f"booking request #{booking_id}"
        )

        session["last_booking_id"] = int(booking_id)
        # OTP verification is single-use; a new booking requires a new code.
        for key in (
            "booking_email_verified", "booking_verified_email",
            "booking_verified_name", "booking_verified_expires"
        ):
            session.pop(key, None)
        session.modified = True

        app.logger.info("BOOKING SAVED: ID %s", booking_id)
        return redirect(url_for("booking_confirmation"))

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("MYSQL BOOKING ERROR")
        return show_form_error(
            "Booking could not be saved because of a database error. Your entered details have been kept. Please try again."
        )

    except Exception:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("UNEXPECTED BOOKING ERROR")
        return show_form_error(
            "An unexpected error occurred. Your entered details have been kept. Please check the terminal or try again."
        )

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()


# ==========================================
# BOOKING CONFIRMATION PAGE
# ==========================================

@app.route("/booking-confirmation")
def booking_confirmation():

    booking_id = session.get("last_booking_id")

    if not booking_id:

        flash("Please submit a booking first.")
        return redirect(url_for("booking"))

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                name,
                email,
                booking_type,
                rate,
                room,
                checkin,
                checkout,
                guests,
                status,
                reservation_fee,
                payment_status,
                gcash_reference,
                receipt_filename
            FROM bookings
            WHERE id = %s
            LIMIT 1
        """, (booking_id,))

        booking_record = cursor.fetchone()

        if not booking_record:

            session.pop("last_booking_id", None)

            flash(
                "Booking not found. Please submit your booking again."
            )

            return redirect(url_for("booking"))

        prices = {
            "Day": 4000,
            "Night": 5000,
            "Full day": 7000
        }

        total_price = booking_record.get("rate")

        if total_price is None:

            total_price = prices.get(
                booking_record["booking_type"],
                0
            )

        reservation_fee = booking_record.get(
            "reservation_fee"
        )

        if reservation_fee is None:
            reservation_fee = 500

        base_prices = {
            "Day": 4000,
            "Night": 5000,
            "Full day": 7000
        }
        base_price = base_prices.get(booking_record["booking_type"], 0)
        room_fee = max(0, int(total_price) - base_price)

        return render_template(
            "booking_confirmation.html",
            booking=booking_record,
            total_price=int(total_price),
            base_price=base_price,
            room_fee=room_fee,
            reservation_fee=int(reservation_fee)
        )

    except mysql.connector.Error:

        app.logger.exception(
            "CONFIRMATION DATABASE ERROR"
        )

        return (
            "Unable to load booking confirmation. "
            "Check the terminal.",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()


# ==========================================
# CUSTOMER PAYMENT SUBMISSION
# ==========================================

@app.route(
    "/booking/<int:booking_id>/payment",
    methods=["POST"]
)
def submit_payment(booking_id):

    # The original booking session may submit its own booking.
    # A logged-in customer may also submit only a booking matching
    # the email on their account.
    is_original_booking_session = (
        session.get("last_booking_id") == booking_id
    )
    is_logged_in_customer = (
        "user_id" in session
        and session.get("user_role") != "admin"
    )

    if not is_original_booking_session and not is_logged_in_customer:
        abort(403)

    return_to_dashboard = (
        not is_original_booking_session
        and is_logged_in_customer
    )
    return_endpoint = (
        "dashboard" if return_to_dashboard
        else "booking_confirmation"
    )

    reference = request.form.get(
        "gcash_reference", ""
    ).strip()

    receipt = request.files.get("receipt")

    if not reference or len(reference) > 100:
        flash(
            "Please enter a valid GCash reference number.",
            "error"
        )
        return redirect(url_for(return_endpoint))

    if not receipt or not receipt.filename:
        flash(
            "Please upload your GCash receipt screenshot.",
            "error"
        )
        return redirect(url_for(return_endpoint))

    if not allowed_receipt(receipt.filename):
        flash(
            "Only JPG, JPEG, PNG, and WEBP images are allowed.",
            "error"
        )
        return redirect(url_for(return_endpoint))

    if not valid_image_signature(receipt):
        flash(
            "The uploaded file is not a valid supported image.",
            "error"
        )
        return redirect(url_for(return_endpoint))

    if not image_extension_matches(receipt.filename, receipt):
        flash(
            "The file extension does not match the image format.",
            "error"
        )
        return redirect(url_for(return_endpoint))

    extension = secure_filename(
        receipt.filename
    ).rsplit(".", 1)[1].lower()

    new_filename = f"{uuid.uuid4().hex}.{extension}"
    new_path = os.path.join(RECEIPT_FOLDER, new_filename)

    db = None
    cursor = None
    old_filename = None
    saved_file = False

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT
                id,
                status,
                payment_status,
                receipt_filename,
                email
            FROM bookings
            WHERE id = %s
            LIMIT 1
        """, (booking_id,))

        booking_record = cursor.fetchone()

        if not booking_record:
            flash("Booking not found.", "error")
            return redirect(url_for(return_endpoint))

        # Check ownership whenever the customer is not using the
        # session that originally created this booking.
        if not is_original_booking_session:
            account_email = (session.get("user_email") or "").strip().lower()
            booking_email = (booking_record[4] or "").strip().lower()

            if not account_email or account_email != booking_email:
                abort(403)

        booking_status = booking_record[1]
        payment_status = booking_record[2]
        old_filename = booking_record[3]

        if booking_status != "Pending":
            flash(
                "This booking has already been processed.",
                "error"
            )
            return redirect(url_for(return_endpoint))

        if payment_status == "Paid":
            flash(
                "This booking's payment has already been verified.",
                "error"
            )
            return redirect(url_for(return_endpoint))

        receipt.save(new_path)
        saved_file = True

        cursor.execute("""
            UPDATE bookings
            SET
                gcash_reference = %s,
                receipt_filename = %s,
                payment_status = 'Pending'
            WHERE id = %s
              AND status = 'Pending'
              AND payment_status <> 'Paid'
        """, (
            reference,
            new_filename,
            booking_id
        ))

        if cursor.rowcount != 1:
            db.rollback()
            if saved_file and os.path.isfile(new_path):
                os.remove(new_path)
            flash(
                "The booking payment status changed. Refresh and try again.",
                "error"
            )
            return redirect(url_for(return_endpoint))

        db.commit()

        if old_filename:
            old_path = os.path.join(
                RECEIPT_FOLDER,
                os.path.basename(old_filename)
            )
            if os.path.isfile(old_path):
                os.remove(old_path)

        flash(
            "Payment reference and receipt submitted successfully. "
            "Please wait for admin verification.",
            "success"
        )

        app.logger.info(
            "PAYMENT SUBMITTED FOR BOOKING ID %s",
            booking_id
        )

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()

        if saved_file and os.path.isfile(new_path):
            os.remove(new_path)

        app.logger.exception("PAYMENT SUBMISSION DATABASE ERROR")
        flash(
            "Unable to submit payment information. Please try again.",
            "error"
        )

    except Exception:
        if db and db.is_connected():
            db.rollback()

        if saved_file and os.path.isfile(new_path):
            os.remove(new_path)

        app.logger.exception("PAYMENT SUBMISSION ERROR")
        flash(
            "An unexpected error occurred while submitting your receipt.",
            "error"
        )

    finally:
        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()

    return redirect(url_for(return_endpoint))


# ==========================================
# CUSTOMER VIEW PAYMENT RECEIPT
# ==========================================

@app.route("/booking/<int:booking_id>/receipt")
def customer_payment_receipt(booking_id):

    # Only the session that created this booking can view its receipt.
    if session.get("last_booking_id") != booking_id:
        abort(403)

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT receipt_filename
            FROM bookings
            WHERE id = %s
            LIMIT 1
        """, (booking_id,))

        record = cursor.fetchone()

        if not record or not record[0]:
            abort(404)

        filename = os.path.basename(record[0])

        receipt_path = os.path.join(
            RECEIPT_FOLDER,
            filename
        )

        if not filename or not os.path.isfile(receipt_path):
            abort(404)

        return send_from_directory(
            RECEIPT_FOLDER,
            filename,
            as_attachment=False
        )

    except mysql.connector.Error:

        app.logger.exception(
            "CUSTOMER VIEW RECEIPT DATABASE ERROR"
        )

        return "Unable to load payment receipt.", 500

    finally:

        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()
            # ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@admin_required
def admin():

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM bookings
            ORDER BY checkin ASC
        """)
        bookings = cursor.fetchall()

        cursor.execute("""
            SELECT id, unavailable_date
            FROM unavailable_dates
            ORDER BY unavailable_date ASC
        """)
        unavailable_dates = cursor.fetchall()

        cursor.execute("""
            SELECT
                COUNT(*) AS total_bookings,
                COALESCE(SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END), 0)
                    AS pending_bookings,
                COALESCE(SUM(CASE WHEN status = 'Confirmed' THEN 1 ELSE 0 END), 0)
                    AS confirmed_bookings,
                COALESCE(SUM(
                    CASE
                        WHEN payment_status = 'Paid'
                        THEN COALESCE(reservation_fee, 0)
                        ELSE 0
                    END
                ), 0) AS reservation_fees_collected
            FROM bookings
        """)
        analytics = cursor.fetchone()

        cursor.execute("""
            SELECT id, admin_id, admin_name, action, details,
                   booking_id, created_at
            FROM admin_activity_logs
            ORDER BY created_at DESC, id DESC
            LIMIT 50
        """)
        activity_logs = cursor.fetchall()

        return render_template(
            "admin.html",
            bookings=bookings,
            unavailable_dates=unavailable_dates,
            today=date.today().isoformat(),
            analytics=analytics,
            activity_logs=activity_logs
        )

    except mysql.connector.Error:
        app.logger.exception("ADMIN DATABASE ERROR")
        return (
            "Unable to load admin dashboard. Check the terminal.",
            500
        )

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()


# ==========================================
# ADMIN EXPORT BOOKINGS TO CSV
# ==========================================

@app.route("/admin/export-bookings")
@admin_required
def export_bookings():
    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id, name, email, room, booking_type,
                checkin, checkout, guests, rate,
                reservation_fee, gcash_reference,
                payment_status, status
            FROM bookings
            ORDER BY id DESC
        """)
        bookings = cursor.fetchall()

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Booking ID", "Customer Name", "Email", "Room",
            "Booking Type", "Check-in", "Check-out", "Guests",
            "Total Rate", "Reservation Fee", "GCash Reference",
            "Payment Status", "Booking Status"
        ])

        for booking in bookings:
            writer.writerow([
                booking.get("id"),
                booking.get("name"),
                booking.get("email"),
                booking.get("room"),
                booking.get("booking_type"),
                booking.get("checkin"),
                booking.get("checkout"),
                booking.get("guests"),
                booking.get("rate"),
                booking.get("reservation_fee"),
                booking.get("gcash_reference"),
                booking.get("payment_status"),
                booking.get("status")
            ])

        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Disposition"] = (
            "attachment; filename=dream_villa_bookings.csv"
        )
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        return response

    except mysql.connector.Error:
        app.logger.exception("CSV EXPORT DATABASE ERROR")
        flash("Unable to export bookings. Please try again.", "error")
        return redirect(url_for("admin"))

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()


# ==========================================
# ADMIN VIEW PAYMENT RECEIPT
# ==========================================

@app.route("/admin/payment-receipt/<int:booking_id>")
@admin_required
def view_payment_receipt(booking_id):

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT receipt_filename
            FROM bookings
            WHERE id = %s
            LIMIT 1
        """, (booking_id,))

        record = cursor.fetchone()

        if not record or not record[0]:
            abort(404)

        filename = os.path.basename(record[0])
        receipt_path = os.path.join(RECEIPT_FOLDER, filename)

        if not filename or not os.path.isfile(receipt_path):
            abort(404)

        return send_from_directory(
            RECEIPT_FOLDER,
            filename,
            as_attachment=False
        )

    except mysql.connector.Error:
        app.logger.exception("VIEW PAYMENT RECEIPT ERROR")
        return "Unable to load payment receipt.", 500

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()


# ==========================================
# ADMIN VERIFY OR REJECT PAYMENT
# ==========================================

@app.route(
    "/admin/payment-status/<int:booking_id>",
    methods=["POST"]
)
@admin_required
def update_payment_status(booking_id):

    payment_decision = request.form.get(
    "payment_decision",
    request.form.get("payment_status", "")
).strip()

    if payment_decision not in ("Paid", "Rejected"):
        flash("Invalid payment action.", "error")
        return redirect(url_for("admin"))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT status, receipt_filename, name, email, booking_type, checkin, checkout, rate
            FROM bookings
            WHERE id = %s
            LIMIT 1
        """, (booking_id,))

        booking_record = cursor.fetchone()

        if not booking_record:
            flash("Booking not found.", "error")
            return redirect(url_for("admin"))

        booking_status, receipt_filename, customer_name, customer_email, booking_type, checkin, checkout, booking_rate = booking_record

        if booking_status != "Pending":
            flash(
                "Payment can only be reviewed while the booking is pending.",
                "error"
            )
            return redirect(url_for("admin"))

        if payment_decision == "Paid":
            if not receipt_filename:
                flash(
                    "There is no receipt uploaded for this booking.",
                    "error"
                )
                return redirect(url_for("admin"))

            safe_filename = os.path.basename(receipt_filename)
            receipt_path = os.path.join(
                RECEIPT_FOLDER,
                safe_filename
            )

            if not safe_filename or not os.path.isfile(receipt_path):
                flash(
                    "The uploaded receipt file could not be found.",
                    "error"
                )
                return redirect(url_for("admin"))

        cursor.execute("""
            UPDATE bookings
            SET payment_status = %s
            WHERE id = %s
              AND status = 'Pending'
        """, (payment_decision, booking_id))

        db.commit()

        if cursor.rowcount:
            if payment_decision == "Paid":
                notify_customer(
                    customer_email,
                    f"Dream Villa - Payment Received (Booking #{booking_id})",
                    f"Hello {customer_name},\n\n"
                    f"Your payment for booking #{booking_id} has been marked as PAID by Dream Villa.\n\n"
                    f"Booking type: {booking_type}\n"
                    f"Booking rate: PHP {float(booking_rate):,.2f}\n"
                    f"Check-in: {checkin.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkin, 'strftime') else checkin}\n"
                    f"Check-out: {checkout.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkout, 'strftime') else checkout}\n\n"
                    "Your booking is still awaiting final confirmation. We will send another email once it is approved.\n\n"
                    "Thank you,\nDream Villa",
                    f"payment marked paid for booking #{booking_id}"
                )
                log_admin_activity(
                    action="Payment Verified",
                    details=f"Admin verified payment for booking #{booking_id}.",
                    booking_id=booking_id
                )
                flash(
                    "Payment marked as Paid. You can now confirm the booking.",
                    "success"
                )
            else:
                notify_customer(
                    customer_email,
                    f"Dream Villa - Payment Needs Attention (Booking #{booking_id})",
                    f"Hello {customer_name},\n\n"
                    f"The payment submitted for booking #{booking_id} could not be verified and has been marked as REJECTED.\n\n"
                    "Please review your payment details and submit a new receipt through the booking page, or contact Dream Villa for assistance.\n\n"
                    "Thank you,\nDream Villa",
                    f"payment rejected for booking #{booking_id}"
                )
                log_admin_activity(
                    action="Payment Rejected",
                    details=f"Admin rejected the payment for booking #{booking_id}.",
                    booking_id=booking_id
                )
                flash(
                    "Payment marked as Rejected. The customer may submit a new receipt.",
                    "success"
                )
        else:
            flash("Payment status was not updated.", "error")

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()

        app.logger.exception("UPDATE PAYMENT STATUS ERROR")
        flash(
            "Unable to update payment status. Check the terminal.",
            "error"
        )

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

    return redirect(url_for("admin"))


# ==========================================
# CONFIRM / APPROVE BOOKING
# ==========================================

@app.route(
    "/admin/confirm/<int:booking_id>",
    methods=["POST"]
)
@admin_required
def confirm_booking(booking_id):

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT
                id,
                status,
                payment_status,
                receipt_filename,
                checkin,
                checkout,
                name,
                email,
                booking_type,
                rate,
                room,
                guests
            FROM bookings
            WHERE id = %s
            LIMIT 1
        """, (booking_id,))

        booking_record = cursor.fetchone()

        if not booking_record:
            flash("Booking not found.", "error")
            return redirect(url_for("admin"))

        (
            _,
            booking_status,
            payment_status,
            receipt_filename,
            checkin,
            checkout,
            customer_name,
            customer_email,
            booking_type,
            booking_rate,
            room,
            guest_count
        ) = booking_record

        if booking_status != "Pending":
            flash(
                "This booking has already been processed.",
                "error"
            )
            return redirect(url_for("admin"))

        # Payment must be manually verified by the admin first.
        if payment_status != "Paid" or not receipt_filename:
            flash(
                "Verify the GCash receipt and mark payment as Paid before confirming.",
                "error"
            )
            return redirect(url_for("admin"))

        safe_filename = os.path.basename(receipt_filename)
        receipt_path = os.path.join(
            RECEIPT_FOLDER,
            safe_filename
        )

        if not safe_filename or not os.path.isfile(receipt_path):
            flash(
                "The payment receipt file is missing. Booking cannot be confirmed.",
                "error"
            )
            return redirect(url_for("admin"))

        # Recheck unavailable dates before confirmation.
        last_occupied_date = checkout.date()

        if checkout.time() == time(0, 0):
            last_occupied_date -= timedelta(days=1)

        cursor.execute("""
            SELECT unavailable_date
            FROM unavailable_dates
            WHERE unavailable_date >= %s
              AND unavailable_date <= %s
            LIMIT 1
        """, (
            checkin.date(),
            last_occupied_date
        ))

        unavailable_record = cursor.fetchone()

        if unavailable_record:
            flash(
                "This booking includes a date that is now unavailable. "
                "Review the reservation before confirming.",
                "error"
            )
            return redirect(url_for("admin"))

        # Recheck overlapping reservations, excluding this booking.
        cursor.execute("""
            SELECT id
            FROM bookings
            WHERE id <> %s
              AND status IN ('Pending', 'Confirmed')
              AND checkin < %s
              AND checkout > %s
            LIMIT 1
        """, (
            booking_id,
            checkout,
            checkin
        ))

        if cursor.fetchone():
            flash(
                "This booking overlaps another active reservation. "
                "Please review it before confirming.",
                "error"
            )
            return redirect(url_for("admin"))

        cursor.execute("""
            UPDATE bookings
            SET status = 'Confirmed'
            WHERE id = %s
              AND status = 'Pending'
              AND payment_status = 'Paid'
        """, (booking_id,))

        db.commit()

        if cursor.rowcount:
            notify_customer(
                customer_email,
                f"Dream Villa - Booking Confirmed (#{booking_id})",
                f"Hello {customer_name},\n\n"
                f"Good news! Your Dream Villa booking #{booking_id} is now CONFIRMED.\n\n"
                f"Booking type: {booking_type}\n"
                f"Room: {room}\n"
                f"Guests: {guest_count}\n"
                f"Check-in: {checkin.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkin, 'strftime') else checkin}\n"
                f"Check-out: {checkout.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkout, 'strftime') else checkout}\n"
                f"Booking rate: PHP {float(booking_rate):,.2f}\n\n"
                "Please keep this email as your booking confirmation. We look forward to welcoming you!\n\n"
                "Thank you,\nDream Villa",
                f"booking confirmed #{booking_id}"
            )
            log_admin_activity(
                action="Booking Confirmed",
                details=f"Admin confirmed booking #{booking_id}.",
                booking_id=booking_id
            )
            flash("Booking confirmed successfully!", "success")
        else:
            flash(
                "The booking could not be confirmed. Refresh and try again.",
                "error"
            )

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()

        app.logger.exception("CONFIRM BOOKING DATABASE ERROR")
        flash(
            "Unable to approve the booking. Check the terminal.",
            "error"
        )

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

    return redirect(url_for("admin"))


# ==========================================
# ADMIN-ONLY CANCEL BOOKING
# ==========================================

@app.route("/admin/cancel-booking/<int:booking_id>", methods=["POST"])
@admin_required
def cancel_booking(booking_id):

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        # Lock the booking row while checking and updating its status.
        cursor.execute("""
            SELECT status, name, email, booking_type, checkin, checkout
            FROM bookings
            WHERE id = %s
            FOR UPDATE
        """, (booking_id,))

        booking_record = cursor.fetchone()

        if not booking_record:
            db.rollback()
            flash("Booking not found.", "error")
            return redirect(url_for("admin"))

        current_status, customer_name, customer_email, booking_type, checkin, checkout = booking_record

        if current_status == "Cancelled":
            db.rollback()
            flash("This booking is already cancelled.", "warning")
            return redirect(url_for("admin"))

        if current_status not in ("Pending", "Confirmed"):
            db.rollback()
            flash("Only pending or confirmed bookings can be cancelled.", "error")
            return redirect(url_for("admin"))

        cursor.execute("""
            UPDATE bookings
            SET status = 'Cancelled'
            WHERE id = %s
              AND status IN ('Pending', 'Confirmed')
        """, (booking_id,))

        if cursor.rowcount != 1:
            db.rollback()
            flash("The booking status changed. Refresh and try again.", "error")
            return redirect(url_for("admin"))

        db.commit()

        notify_customer(
            customer_email,
            f"Dream Villa - Booking Cancelled (#{booking_id})",
            f"Hello {customer_name},\\n\\n"
            f"Your Dream Villa booking #{booking_id} has been cancelled by the resort admin.\\n\\n"
            f"Booking type: {booking_type}\\n"
            f"Check-in: {checkin.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkin, 'strftime') else checkin}\\n"
            f"Check-out: {checkout.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkout, 'strftime') else checkout}\\n\\n"
            "If you have questions about this cancellation or your payment, please contact Dream Villa.\\n\\n"
            "Thank you,\\nDream Villa",
            f"booking cancelled #{booking_id}"
        )

        log_admin_activity(
            action="Booking Cancelled",
            details=f"Admin cancelled booking #{booking_id}.",
            booking_id=booking_id
        )

        flash(f"Booking #{booking_id} has been cancelled.", "success")

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("CANCEL BOOKING ERROR")
        flash("Unable to cancel the booking. Check the terminal.", "error")

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

    return redirect(url_for("admin"))


# ==========================================
# ADMIN UPDATE BOOKING DETAILS
# ==========================================

@app.route("/admin/update-booking/<int:booking_id>", methods=["POST"])
@admin_required
def update_booking_details(booking_id):
    db = None
    cursor = None

    checkin_text = request.form.get("checkin", "").strip()
    checkout_text = request.form.get("checkout", "").strip()
    guests_text = request.form.get("guests", "").strip()

    try:
        new_checkin = datetime.fromisoformat(checkin_text)
        new_checkout = datetime.fromisoformat(checkout_text)
        new_guests = int(guests_text)

        if new_checkout <= new_checkin:
            flash("Check-out must be later than check-in.", "error")
            return redirect(url_for("admin"))

        if not 1 <= new_guests <= 100:
            flash("Guests must be between 1 and 100.", "error")
            return redirect(url_for("admin"))

    except (ValueError, TypeError):
        flash("Enter valid check-in, check-out, and guest details.", "error")
        return redirect(url_for("admin"))

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT status, name, email, booking_type, checkin, checkout, guests
            FROM bookings
            WHERE id = %s
            FOR UPDATE
        """, (booking_id,))
        record = cursor.fetchone()

        if not record:
            db.rollback()
            flash("Booking not found.", "error")
            return redirect(url_for("admin"))

        status, customer_name, customer_email, booking_type, old_checkin, old_checkout, old_guests = record

        if status not in ("Pending", "Confirmed"):
            db.rollback()
            flash("Only pending or confirmed bookings can be edited.", "error")
            return redirect(url_for("admin"))

        if new_checkin < datetime.now():
            db.rollback()
            flash("Check-in must be in the future.", "error")
            return redirect(url_for("admin"))

        last_occupied_date = new_checkout.date()
        if new_checkout.time() == time(0, 0):
            last_occupied_date -= timedelta(days=1)

        cursor.execute("""
            SELECT unavailable_date
            FROM unavailable_dates
            WHERE unavailable_date >= %s AND unavailable_date <= %s
            LIMIT 1
        """, (new_checkin.date(), last_occupied_date))

        if cursor.fetchone():
            db.rollback()
            flash("The selected dates include an unavailable date.", "error")
            return redirect(url_for("admin"))

        cursor.execute("""
            SELECT id
            FROM bookings
            WHERE id <> %s
              AND status IN ('Pending', 'Confirmed')
              AND checkin < %s
              AND checkout > %s
            LIMIT 1
        """, (booking_id, new_checkout, new_checkin))

        if cursor.fetchone():
            db.rollback()
            flash("The updated dates overlap another active booking.", "error")
            return redirect(url_for("admin"))

        cursor.execute("""
            UPDATE bookings
            SET checkin = %s, checkout = %s, guests = %s
            WHERE id = %s
              AND status IN ('Pending', 'Confirmed')
        """, (new_checkin, new_checkout, new_guests, booking_id))

        if cursor.rowcount != 1:
            db.rollback()
            flash("Booking details were not updated. Refresh and try again.", "error")
            return redirect(url_for("admin"))

        db.commit()

        notify_customer(
            customer_email,
            f"Dream Villa - Booking Details Updated (#{booking_id})",
            f"Hello {customer_name},\\n\\n"
            f"The details of your Dream Villa booking #{booking_id} have been updated by the resort admin.\\n\\n"
            f"Booking type: {booking_type}\\n"
            f"Previous check-in: {old_checkin}\\n"
            f"New check-in: {new_checkin.strftime('%B %d, %Y at %I:%M %p')}\\n"
            f"Previous check-out: {old_checkout}\\n"
            f"New check-out: {new_checkout.strftime('%B %d, %Y at %I:%M %p')}\\n"
            f"Previous guests: {old_guests}\\n"
            f"New guests: {new_guests}\\n\\n"
            "Please contact Dream Villa if you have questions.\\n\\n"
            "Thank you,\\nDream Villa",
            f"booking details updated #{booking_id}"
        )

        log_admin_activity(
            action="Booking Details Updated",
            details=f"Admin updated dates/guest count for booking #{booking_id}.",
            booking_id=booking_id
        )
        flash(f"Booking #{booking_id} details updated. Customer notification attempted.", "success")

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("UPDATE BOOKING DETAILS ERROR")
        flash("Unable to update booking details. Check the terminal.", "error")

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

    return redirect(url_for("admin"))


# ==========================================
# ADMIN MARK BOOKING AS COMPLETED
# ==========================================

@app.route("/admin/complete-booking/<int:booking_id>", methods=["POST"])
@admin_required
def complete_booking(booking_id):
    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT status, name, email, booking_type, checkin, checkout, room, guests, rate
            FROM bookings
            WHERE id = %s
            FOR UPDATE
        """, (booking_id,))
        record = cursor.fetchone()

        if not record:
            db.rollback()
            flash("Booking not found.", "error")
            return redirect(url_for("admin"))

        status, customer_name, customer_email, booking_type, checkin, checkout, room, guests, rate = record

        if status != "Confirmed":
            db.rollback()
            flash("Only confirmed bookings can be marked as completed.", "error")
            return redirect(url_for("admin"))

        if datetime.now() < checkout:
            db.rollback()
            flash("This booking cannot be completed before its check-out time.", "error")
            return redirect(url_for("admin"))

        cursor.execute("""
            UPDATE bookings
            SET status = 'Completed'
            WHERE id = %s AND status = 'Confirmed'
        """, (booking_id,))

        if cursor.rowcount != 1:
            db.rollback()
            flash("Booking status was not updated. Refresh and try again.", "error")
            return redirect(url_for("admin"))

        db.commit()

        notify_customer(
            customer_email,
            f"Dream Villa - Booking Completed (#{booking_id})",
            f"Hello {customer_name},\\n\\n"
            f"Thank you for choosing Dream Villa. Your booking #{booking_id} has been marked as COMPLETED.\\n\\n"
            f"Booking type: {booking_type}\\n"
            f"Room: {room}\\n"
            f"Guests: {guests}\\n"
            f"Check-in: {checkin.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkin, 'strftime') else checkin}\\n"
            f"Check-out: {checkout.strftime('%B %d, %Y at %I:%M %p') if hasattr(checkout, 'strftime') else checkout}\\n"
            f"Booking rate: PHP {float(rate):,.2f}\\n\\n"
            "We hope you enjoyed your stay and look forward to welcoming you again.\\n\\n"
            "Thank you,\\nDream Villa",
            f"booking completed #{booking_id}"
        )

        log_admin_activity(
            action="Booking Completed",
            details=f"Admin marked booking #{booking_id} as completed.",
            booking_id=booking_id
        )
        flash(f"Booking #{booking_id} marked as completed.", "success")

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("COMPLETE BOOKING ERROR")
        flash("Unable to complete booking. Check the terminal.", "error")

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

    return redirect(url_for("admin"))


# ==========================================
# ADD UNAVAILABLE DATE
# ==========================================

@app.route(
    "/admin/add-unavailable",
    methods=["POST"]
)
@admin_required
def add_unavailable():

    date_text = request.form.get(
        "unavailable_date", ""
    ).strip()

    try:

        selected_date = date.fromisoformat(
            date_text
        )

        if selected_date < date.today():

            flash(
                "Please select today or a future date."
            )

            return redirect(url_for("admin"))

    except ValueError:

        flash("Please select a valid date.")
        return redirect(url_for("admin"))

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO unavailable_dates (
                unavailable_date
            )
            VALUES (%s)
        """, (selected_date,))

        db.commit()

        log_admin_activity(
            action="Unavailable Date Added",
            details=f"Admin marked {selected_date.isoformat()} as unavailable."
        )

        flash(
            "Unavailable date added successfully."
        )

    except mysql.connector.IntegrityError:

        if db and db.is_connected():
            db.rollback()

        flash(
            "That date is already marked as unavailable."
        )

    except mysql.connector.Error:

        if db and db.is_connected():
            db.rollback()

        app.logger.exception(
            "ADD UNAVAILABLE DATE ERROR"
        )

        flash("Unable to add unavailable date.")

    finally:

        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()

    return redirect(url_for("admin"))


# ==========================================
# DELETE UNAVAILABLE DATE
# ==========================================

@app.route(
    "/admin/delete-unavailable/<int:date_id>",
    methods=["POST"]
)
@admin_required
def delete_unavailable(date_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            DELETE FROM unavailable_dates
            WHERE id = %s
        """, (date_id,))

        db.commit()

        if cursor.rowcount:
            log_admin_activity(
                action="Unavailable Date Removed",
                details=f"Admin removed unavailable date record #{date_id}."
            )
            flash("Unavailable date removed.")
        else:
            flash("Unavailable date not found.")

    except mysql.connector.Error:

        if db and db.is_connected():
            db.rollback()

        app.logger.exception(
            "DELETE UNAVAILABLE DATE ERROR"
        )

        flash("Unable to remove unavailable date.")

    finally:

        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()

    return redirect(url_for("admin"))
# ==========================================
# CUSTOMER REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        fullname = request.form.get(
            "fullname", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not fullname or not email or not password:

            flash("Please complete all required fields.")
            return redirect(url_for("register"))

        if len(fullname) > 100 or len(email) > 100:

            flash("Name or email is too long.")
            return redirect(url_for("register"))

        if password != confirm_password:

            flash("Passwords do not match.")
            return redirect(url_for("register"))

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters."
            )

            return redirect(url_for("register"))

        if not re.search(r"[A-Za-z]", password):
            flash(
                "Password must contain at least one letter. Numbers only are not allowed."
            )
            return redirect(url_for("register"))

        if not re.search(r"[0-9]", password):
            flash(
                "Password must contain at least one number."
            )
            return redirect(url_for("register"))

        db = None
        cursor = None

        try:

            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )

            if cursor.fetchone():

                flash(
                    "Email already registered. Please log in."
                )

                return redirect(url_for("register"))

            password_hash = generate_password_hash(
                password
            )

            cursor.execute("""
                INSERT INTO users (
                    fullname,
                    email,
                    password_hash
                )
                VALUES (%s, %s, %s)
            """, (
                fullname,
                email,
                password_hash
            ))

            db.commit()

            flash(
                "Registration successful. You can now log in.",
                "success"
            )

            return redirect(url_for("login"))

        except mysql.connector.IntegrityError:

            if db and db.is_connected():
                db.rollback()

            flash(
                "Email already registered. Please log in."
            )

        except mysql.connector.Error:

            if db and db.is_connected():
                db.rollback()

            app.logger.exception(
                "REGISTRATION DATABASE ERROR"
            )

            flash(
                "Registration failed. Check the VS Code terminal."
            )

        finally:

            if cursor:
                cursor.close()

            if db and db.is_connected():
                db.close()

        return redirect(url_for("register"))

    return render_template("register.html")


# ==========================================
# CUSTOMER LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    requested_next = request.args.get("next") or session.get("after_login")
    if requested_next == url_for("booking"):
        session["after_login"] = requested_next

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        db = None
        cursor = None

        try:

            db = get_db_connection()
            cursor = db.cursor(dictionary=True)

            cursor.execute("""
                SELECT
                    id,
                    fullname,
                    email,
                    password_hash,
                    role
                FROM users
                WHERE email = %s
            """, (email,))

            user = cursor.fetchone()

            if user and check_password_hash(
                user["password_hash"],
                password
            ):

                # Preserve only the known internal booking destination while
                # clearing any previous login/session data.
                continue_to_booking = (
                    requested_next == url_for("booking")
                    or session.get("after_login") == url_for("booking")
                )
                session.clear()

                session["user_id"] = user["id"]
                session["user_name"] = user["fullname"]
                session["user_email"] = user["email"]
                session["user_role"] = user["role"]

                if user["role"] == "admin":
                    return redirect(url_for("admin"))

                if continue_to_booking:
                    return redirect(url_for("booking"))

                return redirect(url_for("dashboard"))

            flash("Invalid email or password.", "error")

        except mysql.connector.Error:

            app.logger.exception(
                "LOGIN DATABASE ERROR"
            )

            flash(
                "Unable to log in. Check the VS Code terminal."
            )

        finally:

            if cursor:
                cursor.close()

            if db and db.is_connected():
                db.close()

    return render_template("login.html")




# ==========================================
# FORGOT PASSWORD
# ==========================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        generic_message = (
            "If that email is registered, a password reset link will be sent. "
            "Please check your inbox and spam folder."
        )

        if not email or len(email) > 100:
            flash(generic_message, "success")
            return redirect(url_for("login"))

        db = None
        cursor = None

        try:
            db = get_db_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute("""
                SELECT id, fullname, email, password_hash
                FROM users
                WHERE email = %s
                LIMIT 1
            """, (email,))
            user = cursor.fetchone()

            if user:
                serializer = URLSafeTimedSerializer(app.secret_key)
                password_fingerprint = hashlib.sha256(
                    user["password_hash"].encode("utf-8")
                ).hexdigest()

                token = serializer.dumps(
                    {
                        "user_id": user["id"],
                        "password_fingerprint": password_fingerprint
                    },
                    salt="dream-villa-password-reset"
                )

                reset_link = url_for(
                    "reset_password",
                    token=token,
                    _external=True
                )

                send_password_reset_email(
                    user["email"], user["fullname"], reset_link
                )

            flash(generic_message, "success")
            return redirect(url_for("login"))

        except Exception:
            app.logger.exception("PASSWORD RESET EMAIL ERROR")
            flash(
                "We could not send the reset email right now. Please try again later.",
                "error"
            )

        finally:
            if cursor:
                cursor.close()
            if db and db.is_connected():
                db.close()

    return render_template("forgot_password.html")


# ==========================================
# RESET PASSWORD
# ==========================================

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    serializer = URLSafeTimedSerializer(app.secret_key)

    try:
        data = serializer.loads(
            token,
            salt="dream-villa-password-reset",
            max_age=900
        )
    except SignatureExpired:
        flash(
            "Your password reset link has expired. Please request a new one.",
            "error"
        )
        return redirect(url_for("forgot_password"))
    except (BadSignature, TypeError, ValueError):
        flash("Invalid password reset link. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, password_hash
            FROM users
            WHERE id = %s
            LIMIT 1
        """, (data.get("user_id"),))
        user = cursor.fetchone()

        if not user:
            flash("Invalid password reset link.", "error")
            return redirect(url_for("forgot_password"))

        current_fingerprint = hashlib.sha256(
            user["password_hash"].encode("utf-8")
        ).hexdigest()
        token_fingerprint = data.get("password_fingerprint", "")

        if not isinstance(token_fingerprint, str) or not hmac.compare_digest(
            current_fingerprint, token_fingerprint
        ):
            flash(
                "This reset link has already been used or is no longer valid.",
                "error"
            )
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not password_meets_requirements(password):
                flash(
                    "Password must contain at least 8 characters, one letter, and one number.",
                    "error"
                )
                return render_template("reset_password.html")

            if password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template("reset_password.html")

            new_password_hash = generate_password_hash(password)
            cursor.execute("""
                UPDATE users
                SET password_hash = %s
                WHERE id = %s AND password_hash = %s
            """, (new_password_hash, user["id"], user["password_hash"]))

            if cursor.rowcount != 1:
                db.rollback()
                flash(
                    "This reset link is no longer valid. Please request a new one.",
                    "error"
                )
                return redirect(url_for("forgot_password"))

            db.commit()
            flash(
                "Your password has been changed successfully. Please log in.",
                "success"
            )
            return redirect(url_for("login"))

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("RESET PASSWORD DATABASE ERROR")
        flash("Unable to reset your password. Please try again.", "error")
        return redirect(url_for("forgot_password"))

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()

    return render_template("reset_password.html")


# ==========================================
# CUSTOMER PROFILE MANAGEMENT
# ==========================================

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        flash("Please log in to access your profile.", "error")
        return redirect(url_for("login"))

    if session.get("user_role") == "admin":
        return redirect(url_for("admin"))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        if request.method == "POST":
            action = request.form.get("action", "").strip()

            cursor.execute("""
                SELECT id, fullname, email, password_hash
                FROM users
                WHERE id = %s
                LIMIT 1
                FOR UPDATE
            """, (session["user_id"],))
            user = cursor.fetchone()

            if not user:
                session.clear()
                flash("Your account could not be found. Please log in again.", "error")
                return redirect(url_for("login"))

            if action == "update_profile":
                fullname = request.form.get("fullname", "").strip()
                email = request.form.get("email", "").strip().lower()
                parsed_name, parsed_email = parseaddr(email)

                if not fullname or len(fullname) > 100:
                    flash("Please enter a name between 1 and 100 characters.", "error")
                    return redirect(url_for("profile"))

                if (
                    not email
                    or len(email) > 100
                    or parsed_email != email
                    or "@" not in email
                    or email.startswith("@")
                    or email.endswith("@")
                    or any(char.isspace() for char in email)
                ):
                    flash("Please enter a valid email address.", "error")
                    return redirect(url_for("profile"))

                cursor.execute("""
                    SELECT id
                    FROM users
                    WHERE email = %s AND id <> %s
                    LIMIT 1
                """, (email, session["user_id"]))

                if cursor.fetchone():
                    flash("That email address is already used by another account.", "error")
                    return redirect(url_for("profile"))

                old_email = user["email"]

                cursor.execute("""
                    UPDATE users
                    SET fullname = %s, email = %s
                    WHERE id = %s
                """, (fullname, email, session["user_id"]))

                # Bookings are associated with customer accounts by email
                # in this application. Keep the customer's booking history
                # connected when their account email changes.
                if old_email.strip().lower() != email:
                    cursor.execute("""
                        UPDATE bookings
                        SET email = %s
                        WHERE LOWER(email) = LOWER(%s)
                    """, (email, old_email))

                db.commit()

                session["user_name"] = fullname
                session["user_email"] = email
                session.modified = True

                flash("Your profile has been updated successfully.", "success")
                return redirect(url_for("profile"))

            elif action == "change_password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")

                if not check_password_hash(user["password_hash"], current_password):
                    flash("Your current password is incorrect.", "error")
                    return redirect(url_for("profile"))

                if len(new_password) < 8:
                    flash("Your new password must contain at least 8 characters.", "error")
                    return redirect(url_for("profile"))

                if not re.search(r"[A-Za-z]", new_password):
                    flash("Your new password must contain at least one letter. Numbers only are not allowed.", "error")
                    return redirect(url_for("profile"))

                if not re.search(r"[0-9]", new_password):
                    flash("Your new password must contain at least one number.", "error")
                    return redirect(url_for("profile"))

                if new_password != confirm_password:
                    flash("The new passwords do not match.", "error")
                    return redirect(url_for("profile"))

                if new_password == current_password:
                    flash("Your new password must be different from your current password.", "error")
                    return redirect(url_for("profile"))

                new_password_hash = generate_password_hash(new_password)

                cursor.execute("""
                    UPDATE users
                    SET password_hash = %s
                    WHERE id = %s
                """, (new_password_hash, session["user_id"]))

                db.commit()
                flash("Your password has been changed successfully.", "success")
                return redirect(url_for("profile"))

            else:
                flash("Invalid profile action.", "error")
                return redirect(url_for("profile"))

        cursor.execute("""
            SELECT id, fullname, email
            FROM users
            WHERE id = %s
            LIMIT 1
        """, (session["user_id"],))
        user = cursor.fetchone()

        if not user:
            session.clear()
            flash("Your account could not be found. Please log in again.", "error")
            return redirect(url_for("login"))

        return render_template("profile.html", user=user)

    except mysql.connector.Error:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("CUSTOMER PROFILE DATABASE ERROR")
        flash("Unable to update or load your profile. Please try again.", "error")
        return redirect(url_for("dashboard"))

    except Exception:
        if db and db.is_connected():
            db.rollback()
        app.logger.exception("CUSTOMER PROFILE ERROR")
        flash("An unexpected error occurred while processing your profile.", "error")
        return redirect(url_for("dashboard"))

    finally:
        if cursor:
            cursor.close()
        if db and db.is_connected():
            db.close()


# ==========================================
# CUSTOMER DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        flash("Please log in to access your dashboard.")
        return redirect(url_for("login"))

    if session.get("user_role") == "admin":
        return redirect(url_for("admin"))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            SELECT
                id,
                name,
                email,
                booking_type,
                rate,
                room,
                checkin,
                checkout,
                guests,
                status,
                reservation_fee,
                payment_status,
                gcash_reference,
                receipt_filename
            FROM bookings
            WHERE LOWER(email) = LOWER(%s)
            ORDER BY id DESC
        """, (session.get("user_email", ""),))

        bookings = cursor.fetchall()

        return render_template(
            "dashboard.html",
            bookings=bookings
        )

    except mysql.connector.Error:
        app.logger.exception("CUSTOMER DASHBOARD DATABASE ERROR")
        flash(
            "Unable to load your bookings. Please try again.",
            "error"
        )
        return render_template("dashboard.html", bookings=[])

    finally:
        if cursor:
            cursor.close()

        if db and db.is_connected():
            db.close()


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash(
        "You have logged out successfully."
    )

    return redirect(url_for("home"))


# ==========================================
# FILE TOO LARGE ERROR
# ==========================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "Receipt image is too large. Maximum size is 5 MB.",
        "error"
    )

    return redirect(
        url_for("booking_confirmation")
    ), 413


# ==========================================
# RUN WEBSITE
# ==========================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=True)