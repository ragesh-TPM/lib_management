# College Library Management System

A comprehensive desktop application for managing college library operations, built with Python and Tkinter. This system provides separate interfaces for administrators and students with robust book management, transaction tracking, and reporting capabilities.

## Features

### 🔐 Authentication System
- **Dual Login System**: Separate interfaces for administrators and students
- **Secure Password Storage**: SHA-256 password hashing
- **Account Status Management**: Active/inactive student accounts

### 👨‍💼 Admin Features
- **Book Management**: Add, edit, delete, and search books
- **Student Management**: Register students and manage accounts
- **Transaction Processing**: Issue and return books with automatic fine calculation
- **Reporting**: Generate library statistics, overdue reports, and popular books
- **Online Book Search**: Integrate with Open Library API to import books

### 👨‍🎓 Student Features
- **Book Search**: Browse available books with filtering
- **Personal Dashboard**: View issued books and due dates
- **Overdue Alerts**: Visual indicators for overdue books

### 📊 Reporting & Analytics
- Library statistics (books, students, transactions)
- Overdue book tracking
- Popular books analysis
- Fine collection reporting

## Installation

### Prerequisites
- Python 3.7 or higher
- Required packages: `tkinter`, `csv`, `hashlib`, `datetime`, `pathlib`, `requests`

### Setup

1. Clone or download the project files

2. Ensure all required Python packages are installed:
```bash
pip install requests
```

3. Run the application:
```bash
python library_management.py
```

## Default Login Credentials

### Admin Account
- **Username**: `admin`
- **Password**: `admin123`

### Student Accounts
- Students must be registered by an administrator first
- Default student status: active

## File Structure

The system uses CSV files for data storage:

- `admins.csv` - Administrator accounts
- `students.csv` - Student accounts and information
- `books.csv` - Book catalog and inventory
- `transactions.csv` - Issue/return records and fines

## Usage Guide

### For Administrators

#### Book Management
- Add new books manually or via Open Library API
- Edit book details and inventory counts
- Remove books from catalog

#### Student Management
- Register new students with auto-generated IDs
- Edit student profiles
- Activate/deactivate student accounts

#### Transactions
- Issue books to students (14-day loan period)
- Process returns with automatic fine calculation ($5/day overdue)
- Collect feedback during returns

#### Reports
- View library statistics
- Generate overdue book lists
- Analyze popular books

### For Students

#### Dashboard
- View currently issued books
- See due dates and overdue status
- Search available books

#### Book Search
- Search by title, author, or category
- Check availability status
- Browse complete catalog

## API Integration

The system integrates with Open Library API to:
- Search for books by title or author
- Import book details automatically
- Expand library catalog easily

## Fine System

- **Overdue Fine**: $5 per day per book
- **Fine Calculation**: Automatic based on return date
- **Payment Tracking**: Recorded in transaction history

## Data Security

- Passwords stored as SHA-256 hashes
- Session-based authentication
- Role-based access control

## Error Handling

- Comprehensive input validation
- User-friendly error messages
- Data integrity checks
- Duplicate prevention

## Customization

The system can be easily customized:

- Modify loan periods in `issue_book()` method
- Adjust fine rates in `return_book()` method
- Extend user roles by modifying authentication logic
- Add new book categories in the book management interface
