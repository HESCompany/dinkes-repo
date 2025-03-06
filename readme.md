# File Repository & Analytics Web Application

This project is a Flask-based web application that provides a secure file repository with robust analytics, user authentication, and an administration dashboard. It supports file upload, download, preview, search functionality, and comprehensive analytics for system performance, visitor statistics, and file usage.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Models](#database-models)
- [Endpoints & Routes](#endpoints--routes)
- [Security & Authentication](#security--authentication)
- [Scheduler & Logging](#scheduler--logging)
- [Usage](#usage)
- [Credits](#credits)

---

## Overview

This application provides a platform where users can:

- **Upload** academic or research documents (e.g., theses, dissertations, journals).
- **Download** and preview files directly from the browser.
- **Search** for files using various filters.
- **View Analytics** on file usage, system performance, visitor demographics, and more.

The system also includes an administration dashboard for managing users and files, with role-based access control to restrict sensitive actions.

---

## Features

- **User Authentication:**  
  - Login, logout, and password reset via OTP sent by email.
  - Role-based access with an admin role to manage files and users.

- **File Management:**  
  - Upload files (with file type restrictions).
  - Download and preview files (supports PDF, image formats, and DOCX conversion to HTML).
  - Edit and delete files (with user or admin permissions).

- **Analytics:**  
  - File statistics (total files, uploads/download trends).
  - Visitor counts, demographics, and search trends.
  - System performance tracking (CPU and memory usage) with historical logs.
  - Storage usage and tag performance analytics.

- **Security Measures:**  
  - CSRF protection via tokens.
  - CAPTCHA for login and search actions.
  - Password hashing using Werkzeug’s security functions.
  - Input validation and role-based access control to prevent unauthorized access.

- **Background Scheduling:**  
  - Uses APScheduler to periodically log system performance metrics.

- **Email Notifications:**  
  - Sends email notifications for password resets, user account creation, updates, and deletions.

- **University List:**  
  - Loads and serves a list of universities from a CSV file for enhanced search/filtering.

---

