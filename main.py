import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import csv
import os
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import requests

class LibraryManagementSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("College Library Management System")
        self.root.geometry("1200x700")
        self.root.configure(bg="#f0f0f0")
        
        # Data files
        self.admin_file = "admins.csv"
        self.students_file = "students.csv"
        self.books_file = "books.csv"
        self.transactions_file = "transactions.csv"
        
        # Initialize data files
        self.initialize_files()
        
        # Current user
        self.current_user = None
        self.user_type = None
        
        # Show login screen
        self.show_login_screen()
    
    def initialize_files(self):
        """Initialize CSV files if they don't exist"""
        # Admin file
        if not os.path.exists(self.admin_file):
            with open(self.admin_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['admin_id', 'username', 'password_hash', 'full_name'])
                # Default admin: username=admin, password=admin123
                default_pass = self.hash_password('admin123')
                writer.writerow(['ADM001', 'admin', default_pass, 'System Administrator'])
        
        # Students file
        if not os.path.exists(self.students_file):
            with open(self.students_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['student_id', 'username', 'password_hash', 'full_name', 
                               'email', 'department', 'year', 'status'])
        
        # Books file
        if not os.path.exists(self.books_file):
            with open(self.books_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['book_id', 'isbn', 'title', 'author', 'publisher', 
                               'year', 'category', 'total_copies', 'available_copies'])
        
        # Transactions file
        if not os.path.exists(self.transactions_file):
            with open(self.transactions_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['transaction_id', 'student_id', 'book_id', 'issue_date', 
                               'due_date', 'return_date', 'status', 'fine', 'feedback'])  # Add feedback
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Display login screen"""
        self.clear_window()
        
        # Main frame
        main_frame = tk.Frame(self.root, bg="#2c3e50")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Login container
        login_frame = tk.Frame(main_frame, bg="white", padx=40, pady=40)
        login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Title
        title = tk.Label(login_frame, text="Library Management System", 
                        font=("Arial", 24, "bold"), bg="white", fg="#2c3e50")
        title.pack(pady=(0, 30))
        
        # User type selection
        self.login_type = tk.StringVar(value="student")
        
        type_frame = tk.Frame(login_frame, bg="white")
        type_frame.pack(pady=10)
        
        tk.Radiobutton(type_frame, text="Student", variable=self.login_type, 
                      value="student", font=("Arial", 12), bg="white").pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(type_frame, text="Admin", variable=self.login_type, 
                      value="admin", font=("Arial", 12), bg="white").pack(side=tk.LEFT, padx=10)
        
        # Username
        tk.Label(login_frame, text="Username:", font=("Arial", 12), 
                bg="white").pack(anchor=tk.W, pady=(10, 0))
        self.username_entry = tk.Entry(login_frame, font=("Arial", 12), width=30)
        self.username_entry.pack(pady=5, ipady=5)
        
        # Password
        tk.Label(login_frame, text="Password:", font=("Arial", 12), 
                bg="white").pack(anchor=tk.W, pady=(10, 0))
        self.password_entry = tk.Entry(login_frame, font=("Arial", 12), 
                                      width=30, show="*")
        self.password_entry.pack(pady=5, ipady=5)
        
        # Login button
        login_btn = tk.Button(login_frame, text="Login", font=("Arial", 14, "bold"),
                             bg="#3498db", fg="white", padx=40, pady=10,
                             command=self.login)
        login_btn.pack(pady=20)
        
        # Bind Enter key
        self.password_entry.bind('<Return>', lambda e: self.login())
    
    def login(self):
        """Handle login authentication"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        user_type = self.login_type.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        password_hash = self.hash_password(password)
        
        # Check credentials
        file_path = self.admin_file if user_type == "admin" else self.students_file
        
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['username'] == username and row['password_hash'] == password_hash:
                    if user_type == "student" and row['status'] != 'active':
                        messagebox.showerror("Error", "Account is not active")
                        return
                    
                    self.current_user = row
                    self.user_type = user_type
                    
                    if user_type == "admin":
                        self.show_admin_dashboard()
                    else:
                        self.show_student_dashboard()
                    return
        
        messagebox.showerror("Error", "Invalid username or password")
    
    def show_admin_dashboard(self):
        """Display admin dashboard"""
        self.clear_window()
        
        # Header
        header = tk.Frame(self.root, bg="#2c3e50", height=80)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="Admin Dashboard", font=("Arial", 24, "bold"),
                bg="#2c3e50", fg="white").pack(side=tk.LEFT, padx=20, pady=20)
        
        tk.Label(header, text=f"Welcome, {self.current_user['full_name']}", 
                font=("Arial", 12), bg="#2c3e50", fg="white").pack(side=tk.RIGHT, padx=20)
        
        logout_btn = tk.Button(header, text="Logout", command=self.show_login_screen,
                              bg="#e74c3c", fg="white", font=("Arial", 10, "bold"),
                              padx=15, pady=5)
        logout_btn.pack(side=tk.RIGHT, padx=20)
        
        # Main content
        content = tk.Frame(self.root, bg="#ecf0f1")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Button frame
        btn_frame = tk.Frame(content, bg="#ecf0f1")
        btn_frame.pack(pady=20)
        
        buttons = [
            ("Manage Books", self.manage_books),
            ("Manage Students", self.manage_students),
            ("Issue Book", self.issue_book),
            ("Return Book", self.return_book),
            ("View Transactions", self.view_transactions),
            ("Generate Reports", self.generate_reports),
            ("Search Online Books", self.search_online_books)
        ]
        
        for i, (text, command) in enumerate(buttons):
            btn = tk.Button(btn_frame, text=text, command=command,
                          bg="#3498db", fg="white", font=("Arial", 12, "bold"),
                          width=20, height=2)
            btn.grid(row=i//3, column=i%3, padx=10, pady=10)
    
    def manage_books(self):
        """Book management interface"""
        window = tk.Toplevel(self.root)
        window.title("Manage Books")
        window.geometry("1000x600")
        
        # Search frame
        search_frame = tk.Frame(window, bg="#ecf0f1", pady=10)
        search_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(search_frame, text="Search:", font=("Arial", 10), 
                bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        search_entry = tk.Entry(search_frame, font=("Arial", 10), width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        def search_books():
            query = search_entry.get().lower()
            for item in tree.get_children():
                tree.delete(item)
            
            with open(self.books_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if (query in row['title'].lower() or 
                        query in row['author'].lower() or 
                        query in row['isbn'].lower()):
                        tree.insert('', tk.END, values=(
                            row['book_id'], row['isbn'], row['title'], 
                            row['author'], row['publisher'], row['year'],
                            row['category'], row['total_copies'], 
                            row['available_copies']
                        ))
        
        tk.Button(search_frame, text="Search", command=search_books,
                 bg="#3498db", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(search_frame, text="Refresh", command=lambda: load_books(),
                 bg="#95a5a6", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        btn_frame = tk.Frame(window, bg="#ecf0f1", pady=10)
        btn_frame.pack(fill=tk.X, padx=10)
        
        tk.Button(btn_frame, text="Add Book", command=lambda: self.add_book(tree),
                 bg="#27ae60", fg="white", font=("Arial", 10, "bold"),
                 padx=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Edit Book", command=lambda: self.edit_book(tree),
                 bg="#f39c12", fg="white", font=("Arial", 10, "bold"),
                 padx=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete Book", command=lambda: self.delete_book(tree),
                 bg="#e74c3c", fg="white", font=("Arial", 10, "bold"),
                 padx=15).pack(side=tk.LEFT, padx=5)
        
        # Treeview
        tree_frame = tk.Frame(window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ('ID', 'ISBN', 'Title', 'Author', 'Publisher', 'Year', 
                  'Category', 'Total', 'Available')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                           yscrollcommand=scrollbar.set)
        scrollbar.config(command=tree.yview)
        
        # Column headings
        widths = [80, 120, 200, 150, 120, 80, 100, 80, 80]
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        def load_books():
            for item in tree.get_children():
                tree.delete(item)
            
            with open(self.books_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    tree.insert('', tk.END, values=(
                        row['book_id'], row['isbn'], row['title'], 
                        row['author'], row['publisher'], row['year'],
                        row['category'], row['total_copies'], 
                        row['available_copies']
                    ))
        
        load_books()
    
    def add_book(self, tree, load_books):
        """Add new book"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Book")
        dialog.geometry("400x500")
        dialog.configure(bg="white")
        
        # Generate book ID
        book_id = f"BK{self.get_next_id(self.books_file, 'BK'):05d}"
        
        fields = [
            ("Book ID:", book_id, 'disabled'),
            ("ISBN:", "", 'normal'),
            ("Title:", "", 'normal'),
            ("Author:", "", 'normal'),
            ("Publisher:", "", 'normal'),
            ("Year:", "", 'normal'),
            ("Category:", "", 'normal'),
            ("Total Copies:", "", 'normal')
        ]
        
        entries = {}
        for i, (label, default, state) in enumerate(fields):
            tk.Label(dialog, text=label, bg="white", font=("Arial", 10)).grid(
                row=i, column=0, sticky=tk.W, padx=20, pady=10)
            entry = tk.Entry(dialog, font=("Arial", 10), width=25, state=state)
            entry.grid(row=i, column=1, padx=20, pady=10)
            if default:
                entry.insert(0, default)
            entries[label] = entry
        
        def save_book():
            try:
                total = int(entries["Total Copies:"].get())
                
                with open(self.books_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        book_id,
                        entries["ISBN:"].get().strip(),
                        entries["Title:"].get().strip(),
                        entries["Author:"].get().strip(),
                        entries["Publisher:"].get().strip(),
                        entries["Year:"].get().strip(),
                        entries["Category:"].get().strip(),
                        total,
                        total  # Available copies = total initially
                    ])
                
                messagebox.showinfo("Success", "Book added successfully!")
                dialog.destroy()
                
                # Refresh tree from file
                load_books()
            except ValueError:
                messagebox.showerror("Error", "Total Copies must be a number")

        tk.Button(dialog, text="Save", command=save_book, bg="#27ae60",
                 fg="white", font=("Arial", 11, "bold"), padx=30,
                 pady=5).grid(row=len(fields), column=0, columnspan=2, pady=20)
    
    def edit_book(self, tree):
        """Edit selected book"""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a book to edit")
            return
        
        item = tree.item(selected[0])
        values = item['values']
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Book")
        dialog.geometry("400x500")
        dialog.configure(bg="white")
        
        fields = [
            ("Book ID:", values[0], 'disabled'),
            ("ISBN:", values[1], 'normal'),
            ("Title:", values[2], 'normal'),
            ("Author:", values[3], 'normal'),
            ("Publisher:", values[4], 'normal'),
            ("Year:", values[5], 'normal'),
            ("Category:", values[6], 'normal'),
            ("Total Copies:", values[7], 'normal')
        ]
        
        entries = {}
        for i, (label, default, state) in enumerate(fields):
            tk.Label(dialog, text=label, bg="white", font=("Arial", 10)).grid(
                row=i, column=0, sticky=tk.W, padx=20, pady=10)
            entry = tk.Entry(dialog, font=("Arial", 10), width=25, state=state)
            entry.grid(row=i, column=1, padx=20, pady=10)
            if state == 'normal':
                entry.insert(0, default)
            else:
                entry.config(state='normal')
                entry.insert(0, default)
                entry.config(state='disabled')
            entries[label] = entry
        
        def update_book():
            try:
                new_total = int(entries["Total Copies:"].get())
                old_total = int(values[7])
                old_available = int(values[8])
                
                # Calculate new available copies
                new_available = old_available + (new_total - old_total)
                if new_available < 0:
                    messagebox.showerror("Error", 
                        "Cannot reduce total copies below issued copies")
                    return
                
                # Update CSV
                rows = []
                with open(self.books_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row['book_id'] == values[0]:
                            row['isbn'] = entries["ISBN:"].get().strip()
                            row['title'] = entries["Title:"].get().strip()
                            row['author'] = entries["Author:"].get().strip()
                            row['publisher'] = entries["Publisher:"].get().strip()
                            row['year'] = entries["Year:"].get().strip()
                            row['category'] = entries["Category:"].get().strip()
                            row['total_copies'] = new_total
                            row['available_copies'] = new_available
                        rows.append(row)
                
                with open(self.books_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                
                messagebox.showinfo("Success", "Book updated successfully!")
                dialog.destroy()
                
                # Update tree
                tree.item(selected[0], values=(
                    values[0], entries["ISBN:"].get().strip(),
                    entries["Title:"].get().strip(), entries["Author:"].get().strip(),
                    entries["Publisher:"].get().strip(), entries["Year:"].get().strip(),
                    entries["Category:"].get().strip(), new_total, new_available
                ))
            except ValueError:
                messagebox.showerror("Error", "Total Copies must be a number")
        
        tk.Button(dialog, text="Update", command=update_book, bg="#f39c12",
                 fg="white", font=("Arial", 11, "bold"), padx=30,
                 pady=5).grid(row=len(fields), column=0, columnspan=2, pady=20)
    
    def delete_book(self, tree):
        """Delete selected book"""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a book to delete")
            return
        
        item = tree.item(selected[0])
        values = item['values']
        
        # Check if book is currently issued
        if int(values[8]) < int(values[7]):
            messagebox.showerror("Error", 
                "Cannot delete book with issued copies. Return all copies first.")
            return
        
        if messagebox.askyesno("Confirm", 
            f"Are you sure you want to delete '{values[2]}'?"):
            
            rows = []
            with open(self.books_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['book_id'] != values[0]:
                        rows.append(row)
            
            with open(self.books_file, 'w', newline='') as f:
                if rows:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
            
            tree.delete(selected[0])
            messagebox.showinfo("Success", "Book deleted successfully!")
    
    def manage_students(self):
        """Student management interface"""
        window = tk.Toplevel(self.root)
        window.title("Manage Students")
        window.geometry("1000x600")
        
        # Search frame
        search_frame = tk.Frame(window, bg="#ecf0f1", pady=10)
        search_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(search_frame, text="Search:", font=("Arial", 10), 
                bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        search_entry = tk.Entry(search_frame, font=("Arial", 10), width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        def search_students():
            query = search_entry.get().lower()
            for item in tree.get_children():
                tree.delete(item)
            
            with open(self.students_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if (query in row['full_name'].lower() or 
                        query in row['student_id'].lower() or 
                        query in row['email'].lower()):
                        tree.insert('', tk.END, values=(
                            row['student_id'], row['username'], row['full_name'],
                            row['email'], row['department'], row['year'], 
                            row['status']
                        ))
        
        tk.Button(search_frame, text="Search", command=search_students,
                 bg="#3498db", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(search_frame, text="Refresh", command=lambda: load_students(),
                 bg="#95a5a6", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        btn_frame = tk.Frame(window, bg="#ecf0f1", pady=10)
        btn_frame.pack(fill=tk.X, padx=10)
        
        tk.Button(btn_frame, text="Add Student", 
                 command=lambda: self.add_student(tree),
                 bg="#27ae60", fg="white", font=("Arial", 10, "bold"),
                 padx=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Edit Student", 
                 command=lambda: self.edit_student(tree),
                 bg="#f39c12", fg="white", font=("Arial", 10, "bold"),
                 padx=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Toggle Status", 
                 command=lambda: self.toggle_student_status(tree),
                 bg="#9b59b6", fg="white", font=("Arial", 10, "bold"),
                 padx=15).pack(side=tk.LEFT, padx=5)
        
        # Treeview
        tree_frame = tk.Frame(window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ('ID', 'Username', 'Name', 'Email', 'Department', 'Year', 'Status')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                           yscrollcommand=scrollbar.set)
        scrollbar.config(command=tree.yview)
        
        widths = [100, 120, 180, 200, 150, 80, 100]
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        def load_students():
            for item in tree.get_children():
                tree.delete(item)
            
            with open(self.students_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    tree.insert('', tk.END, values=(
                        row['student_id'], row['username'], row['full_name'],
                        row['email'], row['department'], row['year'], 
                        row['status']
                    ))
        
        load_students()
    
    def add_student(self, tree):
        """Add new student"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Student")
        dialog.geometry("400x550")
        dialog.configure(bg="white")
        
        student_id = f"STU{self.get_next_id(self.students_file, 'STU'):05d}"
        
        fields = [
            ("Student ID:", student_id, 'disabled'),
            ("Username:", "", 'normal'),
            ("Password:", "", 'normal'),
            ("Full Name:", "", 'normal'),
            ("Email:", "", 'normal'),
            ("Department:", "", 'normal'),
            ("Year:", "", 'normal')
        ]
        
        entries = {}
        for i, (label, default, state) in enumerate(fields):
            tk.Label(dialog, text=label, bg="white", font=("Arial", 10)).grid(
                row=i, column=0, sticky=tk.W, padx=20, pady=10)
            
            if label == "Password:":
                entry = tk.Entry(dialog, font=("Arial", 10), width=25, 
                               state=state, show="*")
            else:
                entry = tk.Entry(dialog, font=("Arial", 10), width=25, state=state)
            
            entry.grid(row=i, column=1, padx=20, pady=10)
            if default:
                entry.insert(0, default)
            entries[label] = entry
        
        def save_student():
            username = entries["Username:"].get().strip()
            password = entries["Password:"].get().strip()
            
            if not username or not password:
                messagebox.showerror("Error", "Username and password are required")
                return
            
            # Check if username exists
            with open(self.students_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['username'] == username:
                        messagebox.showerror("Error", "Username already exists")
                        return
            
            password_hash = self.hash_password(password)
            
            with open(self.students_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    student_id,
                    username,
                    password_hash,
                    entries["Full Name:"].get().strip(),
                    entries["Email:"].get().strip(),
                    entries["Department:"].get().strip(),
                    entries["Year:"].get().strip(),
                    'active'
                ])
            
            messagebox.showinfo("Success", 
                f"Student added successfully!\nUsername: {username}\nPassword: {password}")
            dialog.destroy()
            
            tree.insert('', tk.END, values=(
                student_id, username, entries["Full Name:"].get().strip(),
                entries["Email:"].get().strip(), entries["Department:"].get().strip(),
                entries["Year:"].get().strip(), 'active'
            ))
        
        tk.Button(dialog, text="Save", command=save_student, bg="#27ae60",
                 fg="white", font=("Arial", 11, "bold"), padx=30,
                 pady=5).grid(row=len(fields), column=0, columnspan=2, pady=20)
    
    def edit_student(self, tree):
        """Edit selected student"""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a student to edit")
            return
        
        item = tree.item(selected[0])
        values = item['values']
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Student")
        dialog.geometry("400x500")
        dialog.configure(bg="white")
        
        fields = [
            ("Student ID:", values[0], 'disabled'),
            ("Username:", values[1], 'disabled'),
            ("Full Name:", values[2], 'normal'),
            ("Email:", values[3], 'normal'),
            ("Department:", values[4], 'normal'),
            ("Year:", values[5], 'normal')
        ]
        
        entries = {}
        for i, (label, default, state) in enumerate(fields):
            tk.Label(dialog, text=label, bg="white", font=("Arial", 10)).grid(
                row=i, column=0, sticky=tk.W, padx=20, pady=10)
            entry = tk.Entry(dialog, font=("Arial", 10), width=25, state=state)
            entry.grid(row=i, column=1, padx=20, pady=10)
            if state == 'normal':
                entry.insert(0, default)
            else:
                entry.config(state='normal')
                entry.insert(0, default)
                entry.config(state='disabled')
            entries[label] = entry
        
        def update_student():
            rows = []
            with open(self.students_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['student_id'] == values[0]:
                        row['full_name'] = entries["Full Name:"].get().strip()
                        row['email'] = entries["Email:"].get().strip()
                        row['department'] = entries["Department:"].get().strip()
                        row['year'] = entries["Year:"].get().strip()
                    rows.append(row)
            
            with open(self.students_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            
            messagebox.showinfo("Success", "Student updated successfully!")
            dialog.destroy()
            
            tree.item(selected[0], values=(
                values[0], values[1], entries["Full Name:"].get().strip(),
                entries["Email:"].get().strip(), entries["Department:"].get().strip(),
                entries["Year:"].get().strip(), values[6]
            ))
        
        tk.Button(dialog, text="Update", command=update_student, bg="#f39c12",
                 fg="white", font=("Arial", 11, "bold"), padx=30,
                 pady=5).grid(row=len(fields), column=0, columnspan=2, pady=20)
    
    def toggle_student_status(self, tree):
        """Toggle student active/inactive status"""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a student")
            return
        
        item = tree.item(selected[0])
        values = item['values']
        current_status = values[6]
        new_status = 'inactive' if current_status == 'active' else 'active'
        
        rows = []
        with open(self.students_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['student_id'] == values[0]:
                    row['status'] = new_status
                rows.append(row)
        
        with open(self.students_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        
        tree.item(selected[0], values=(
            values[0], values[1], values[2], values[3], 
            values[4], values[5], new_status
        ))
        
        messagebox.showinfo("Success", f"Student status changed to {new_status}")
    
    def issue_book(self):
        """Issue book to student"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Issue Book")
        dialog.geometry("500x400")
        dialog.configure(bg="white")
        
        tk.Label(dialog, text="Issue Book", font=("Arial", 18, "bold"),
                bg="white").pack(pady=20)
        
        # Student ID
        tk.Label(dialog, text="Student ID:", font=("Arial", 11),
                bg="white").pack(anchor=tk.W, padx=40, pady=(10, 0))
        student_entry = tk.Entry(dialog, font=("Arial", 11), width=30)
        student_entry.pack(padx=40, pady=5)
        
        # Book ID
        tk.Label(dialog, text="Book ID:", font=("Arial", 11),
                bg="white").pack(anchor=tk.W, padx=40, pady=(10, 0))
        book_entry = tk.Entry(dialog, font=("Arial", 11), width=30)
        book_entry.pack(padx=40, pady=5)
        
        # Info label
        info_label = tk.Label(dialog, text="", font=("Arial", 9),
                             bg="white", fg="#7f8c8d", wraplength=400)
        info_label.pack(pady=10)
        
        def verify_and_issue():
            student_id = student_entry.get().strip()
            book_id = book_entry.get().strip()
            
            if not student_id or not book_id:
                messagebox.showerror("Error", "Please enter both Student ID and Book ID")
                return
            
            # Verify student
            student_found = False
            with open(self.students_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['student_id'] == student_id and row['status'] == 'active':
                        student_found = True
                        student_name = row['full_name']
                        break
            
            if not student_found:
                messagebox.showerror("Error", "Student not found or inactive")
                return
            
            # Verify book and availability
            book_found = False
            with open(self.books_file, 'r') as f:
                reader = csv.DictReader(f)
                books = list(reader)
                for i, row in enumerate(books):
                    if row['book_id'] == book_id:
                        book_found = True
                        if int(row['available_copies']) > 0:
                            # Update available copies
                            books[i]['available_copies'] = str(int(row['available_copies']) - 1)
                            book_title = row['title']
                            
                            # Write back to file
                            with open(self.books_file, 'w', newline='') as wf:
                                writer = csv.DictWriter(wf, fieldnames=books[0].keys())
                                writer.writeheader()
                                writer.writerows(books)
                            
                            # Create transaction
                            trans_id = f"TR{self.get_next_id(self.transactions_file, 'TR'):06d}"
                            issue_date = datetime.now().strftime("%Y-%m-%d")
                            due_date = (datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d")
                            
                            with open(self.transactions_file, 'a', newline='') as f:
                                writer = csv.writer(f)
                                writer.writerow([
                                    trans_id, student_id, book_id, issue_date,
                                    due_date, '', 'issued', 0, ''
                                ])
                            
                            messagebox.showinfo("Success", 
                                f"Book issued successfully!\n\n"
                                f"Student: {student_name}\n"
                                f"Book: {book_title}\n"
                                f"Due Date: {due_date}")
                            dialog.destroy()
                            return
                        else:
                            messagebox.showerror("Error", "Book not available (all copies issued)")
                            return
            
            if not book_found:
                messagebox.showerror("Error", "Book not found")
        
        tk.Button(dialog, text="Issue Book", command=verify_and_issue,
                 bg="#27ae60", fg="white", font=("Arial", 12, "bold"),
                 padx=30, pady=10).pack(pady=20)
    
    def return_book(self):
        """Return book from student"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Return Book")
        dialog.geometry("500x450")
        dialog.configure(bg="white")
        
        tk.Label(dialog, text="Return Book", font=("Arial", 18, "bold"),
                bg="white").pack(pady=20)
        
        # Transaction ID or Student ID
        tk.Label(dialog, text="Transaction ID or Student ID:", font=("Arial", 11),
                bg="white").pack(anchor=tk.W, padx=40, pady=(10, 0))
        search_entry = tk.Entry(dialog, font=("Arial", 11), width=30)
        search_entry.pack(padx=40, pady=5)
        
        # Issued books list
        tk.Label(dialog, text="Issued Books:", font=("Arial", 11),
                bg="white").pack(anchor=tk.W, padx=40, pady=(15, 5))
        
        list_frame = tk.Frame(dialog, bg="white")
        list_frame.pack(padx=40, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        books_listbox = tk.Listbox(list_frame, font=("Arial", 9),
                                   yscrollcommand=scrollbar.set, height=8)
        books_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=books_listbox.yview)
        
        transactions = []
        
        def search_issued_books():
            search_term = search_entry.get().strip()
            if not search_term:
                messagebox.showwarning("Warning", "Please enter Transaction ID or Student ID")
                return
            
            books_listbox.delete(0, tk.END)
            transactions.clear()
            
            with open(self.transactions_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['status'] == 'issued' and \
                       (row['transaction_id'] == search_term or row['student_id'] == search_term):
                        # Get book details
                        with open(self.books_file, 'r') as bf:
                            book_reader = csv.DictReader(bf)
                            for book in book_reader:
                                if book['book_id'] == row['book_id']:
                                    transactions.append(row)
                                    display = f"{row['transaction_id']} - {book['title']} (Due: {row['due_date']})"
                                    books_listbox.insert(tk.END, display)
                                    break
            
            if not transactions:
                messagebox.showinfo("Info", "No issued books found")
        
        tk.Button(dialog, text="Search", command=search_issued_books,
                 bg="#3498db", fg="white", font=("Arial", 10, "bold"),
                 padx=20).pack(pady=10)
        
        def process_return():
            selection = books_listbox.curselection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a book to return")
                return
            
            trans = transactions[selection[0]]
            return_date = datetime.now().strftime("%Y-%m-%d")
            
            # Calculate fine for overdue books
            due = datetime.strptime(trans['due_date'], "%Y-%m-%d")
            ret = datetime.strptime(return_date, "%Y-%m-%d")
            days_late = (ret - due).days
            fine = max(0, days_late * 5)  # $5 per day late

            # Prompt for feedback
            feedback = simpledialog.askstring("Feedback", "Please provide feedback for this book (optional):", parent=dialog)
            if feedback is None:
                feedback = ""

            # Update transaction
            rows = []
            with open(self.transactions_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['transaction_id'] == trans['transaction_id']:
                        row['return_date'] = return_date
                        row['status'] = 'returned'
                        row['fine'] = fine
                        row['feedback'] = feedback
                    rows.append(row)
            
            with open(self.transactions_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            
            # Update book availability
            books = []
            with open(self.books_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['book_id'] == trans['book_id']:
                        row['available_copies'] = str(int(row['available_copies']) + 1)
                    books.append(row)
            
            with open(self.books_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=books[0].keys())
                writer.writeheader()
                writer.writerows(books)
            
            fine_msg = f"\nFine: ${fine}" if fine > 0 else "\nNo fine"
            messagebox.showinfo("Success", f"Book returned successfully!{fine_msg}")
            dialog.destroy()
    
        tk.Button(dialog, text="Return Book", command=process_return,
                 bg="#27ae60", fg="white", font=("Arial", 12, "bold"),
                 padx=30, pady=10).pack(pady=10)
    
    def view_transactions(self):
        """View all transactions"""
        window = tk.Toplevel(self.root)
        window.title("Transaction History")
        window.geometry("1100x600")
        
        # Filter frame
        filter_frame = tk.Frame(window, bg="#ecf0f1", pady=10)
        filter_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(filter_frame, text="Filter:", font=("Arial", 10),
                bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        
        filter_var = tk.StringVar(value="all")
        tk.Radiobutton(filter_frame, text="All", variable=filter_var,
                      value="all", bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_frame, text="Issued", variable=filter_var,
                      value="issued", bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_frame, text="Returned", variable=filter_var,
                      value="returned", bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_frame, text="Overdue", variable=filter_var,
                      value="overdue", bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        
        search_entry = tk.Entry(filter_frame, font=("Arial", 10), width=25)
        search_entry.pack(side=tk.LEFT, padx=10)
        
        # Treeview
        tree_frame = tk.Frame(window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ('Trans ID', 'Student ID', 'Book ID', 'Issue Date', 
                  'Due Date', 'Return Date', 'Status', 'Fine', 'Feedback')  # Added 'Feedback'
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                           yscrollcommand=scrollbar.set)
        scrollbar.config(command=tree.yview)
        
        widths = [100, 100, 100, 100, 100, 100, 100, 80, 200]  # Added width for Feedback
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        def load_transactions():
            tree.delete(*tree.get_children())
            filter_val = filter_var.get()
            search_val = search_entry.get().lower()
            with open(self.transactions_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Filtering logic
                    if filter_val != "all" and row['status'] != filter_val:
                        if not (filter_val == "overdue" and row['status'] == "issued" and
                                datetime.strptime(row['due_date'], "%Y-%m-%d") < datetime.now()):
                            continue
                    if search_val and search_val not in str(row).lower():
                        continue
                    tree.insert('', tk.END, values=(
                        row.get('transaction_id', ''),
                        row.get('student_id', ''),
                        row.get('book_id', ''),
                        row.get('issue_date', ''),
                        row.get('due_date', ''),
                        row.get('return_date', ''),
                        row.get('status', ''),
                        row.get('fine', ''),
                        row.get('feedback', '')  # Show feedback
                    ))
        
        # Bind filter/search to reload
        filter_var.trace_add('write', lambda *args: load_transactions())
        search_entry.bind('<KeyRelease>', lambda e: load_transactions())
        
        load_transactions()
    
    def generate_reports(self):
        """Generate various reports"""
        window = tk.Toplevel(self.root)
        window.title("Reports")
        window.geometry("600x500")
        window.configure(bg="white")
        
        tk.Label(window, text="Library Reports", font=("Arial", 20, "bold"),
                bg="white").pack(pady=30)
        
        report_frame = tk.Frame(window, bg="white")
        report_frame.pack(pady=20)
        
        def show_stats():
            # Count statistics
            with open(self.books_file, 'r') as f:
                books = list(csv.DictReader(f))
                total_books = sum(int(b['total_copies']) for b in books)
                unique_books = len(books)
                issued_books = sum(int(b['total_copies']) - int(b['available_copies']) 
                                 for b in books)
            
            with open(self.students_file, 'r') as f:
                students = list(csv.DictReader(f))
                total_students = len(students)
                active_students = sum(1 for s in students if s['status'] == 'active')
            
            with open(self.transactions_file, 'r') as f:
                transactions = list(csv.DictReader(f))
                total_trans = len(transactions)
                active_trans = sum(1 for t in transactions if t['status'] == 'issued')
                total_fines = sum(float(t['fine']) for t in transactions if t['fine'])
            
            msg = f"""Library Statistics:
            
Books:
  • Total Copies: {total_books}
  • Unique Titles: {unique_books}
  • Currently Issued: {issued_books}
  • Available: {total_books - issued_books}

Students:
  • Total Registered: {total_students}
  • Active Students: {active_students}
  • Inactive Students: {total_students - active_students}

Transactions:
  • Total Transactions: {total_trans}
  • Active Issues: {active_trans}
  • Total Fines Collected: ${total_fines:.2f}
"""
            
            messagebox.showinfo("Library Statistics", msg)
        
        def show_overdue():
            today = datetime.now().date()
            overdue = []
            
            with open(self.transactions_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['status'] == 'issued':
                        due = datetime.strptime(row['due_date'], "%Y-%m-%d").date()
                        if due < today:
                            days_late = (today - due).days
                            overdue.append(f"{row['student_id']} - {row['book_id']} "
                                         f"({days_late} days overdue)")
            
            if overdue:
                msg = "Overdue Books:\n\n" + "\n".join(overdue[:20])
                if len(overdue) > 20:
                    msg += f"\n\n... and {len(overdue) - 20} more"
            else:
                msg = "No overdue books!"
            
            messagebox.showinfo("Overdue Books", msg)
        
        def show_popular():
            book_count = {}
            
            with open(self.transactions_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    book_id = row['book_id']
                    book_count[book_id] = book_count.get(book_id, 0) + 1
            
            # Get top 10
            sorted_books = sorted(book_count.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Get book titles
            book_titles = {}
            with open(self.books_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    book_titles[row['book_id']] = row['title']
            
            msg = "Most Popular Books:\n\n"
            for i, (book_id, count) in enumerate(sorted_books, 1):
                title = book_titles.get(book_id, "Unknown")
                msg += f"{i}. {title[:40]} - {count} issues\n"
            
            messagebox.showinfo("Popular Books", msg)
        
        buttons = [
            ("Library Statistics", show_stats),
            ("Overdue Books Report", show_overdue),
            ("Most Popular Books", show_popular)
        ]
        
        for text, command in buttons:
            tk.Button(report_frame, text=text, command=command,
                     bg="#3498db", fg="white", font=("Arial", 12, "bold"),
                     width=25, height=2).pack(pady=10)
    
    def show_student_dashboard(self):
        """Display student dashboard"""
        self.clear_window()
        
        # Header
        header = tk.Frame(self.root, bg="#16a085", height=80)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="Student Portal", font=("Arial", 24, "bold"),
                bg="#16a085", fg="white").pack(side=tk.LEFT, padx=20, pady=20)
        
        tk.Label(header, text=f"Welcome, {self.current_user['full_name']}", 
                font=("Arial", 12), bg="#16a085", fg="white").pack(side=tk.RIGHT, padx=20)
        
        logout_btn = tk.Button(header, text="Logout", command=self.show_login_screen,
                              bg="#e74c3c", fg="white", font=("Arial", 10, "bold"),
                              padx=15, pady=5)
        logout_btn.pack(side=tk.RIGHT, padx=20)
        
        # Main content
        content = tk.Frame(self.root, bg="#ecf0f1")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # My Books section
        tk.Label(content, text="My Issued Books", font=("Arial", 16, "bold"),
                bg="#ecf0f1").pack(anchor=tk.W, pady=(0, 10))
        
        tree_frame = tk.Frame(content)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ('Trans ID', 'Book Title', 'Author', 'Issue Date', 'Due Date', 'Status')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                           yscrollcommand=scrollbar.set, height=8)
        scrollbar.config(command=tree.yview)
        
        widths = [100, 250, 200, 100, 100, 100]
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Load issued books
        today = datetime.now().date()
        with open(self.transactions_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['student_id'] == self.current_user['student_id'] and \
                   row['status'] == 'issued':
                    # Get book details
                    with open(self.books_file, 'r') as bf:
                        book_reader = csv.DictReader(bf)
                        for book in book_reader:
                            if book['book_id'] == row['book_id']:
                                due = datetime.strptime(row['due_date'], "%Y-%m-%d").date()
                                status = "OVERDUE" if due < today else "Active"
                                
                                tree.insert('', tk.END, values=(
                                    row['transaction_id'], book['title'], book['author'],
                                    row['issue_date'], row['due_date'], status
                                ), tags=(status,))
                                break
        
        tree.tag_configure('OVERDUE', foreground='red')
        
        # Search Books button
        tk.Button(content, text="Search Books", command=self.student_search_books,
                 bg="#3498db", fg="white", font=("Arial", 12, "bold"),
                 padx=30, pady=10).pack(pady=10)
    
    def student_search_books(self):
        """Student book search interface"""
        window = tk.Toplevel(self.root)
        window.title("Search Books")
        window.geometry("900x600")
        
        # Search frame
        search_frame = tk.Frame(window, bg="#ecf0f1", pady=15)
        search_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(search_frame, text="Search:", font=("Arial", 11),
                bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        search_entry = tk.Entry(search_frame, font=("Arial", 11), width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        def search_books():
            query = search_entry.get().lower()
            for item in tree.get_children():
                tree.delete(item)
            
            with open(self.books_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if (query in row['title'].lower() or 
                        query in row['author'].lower() or 
                        query in row['category'].lower()):
                        availability = "Available" if int(row['available_copies']) > 0 else "Not Available"
                        tree.insert('', tk.END, values=(
                            row['book_id'], row['title'], row['author'],
                            row['publisher'], row['category'], 
                            row['available_copies'], availability
                        ))
        
        tk.Button(search_frame, text="Search", command=search_books,
                 bg="#3498db", fg="white", font=("Arial", 10, "bold"),
                 padx=20).pack(side=tk.LEFT, padx=5)
        
        # Treeview
        tree_frame = tk.Frame(window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ('Book ID', 'Title', 'Author', 'Publisher', 'Category', 
                  'Available', 'Status')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                           yscrollcommand=scrollbar.set)
        scrollbar.config(command=tree.yview)
        
        widths = [80, 200, 150, 120, 100, 80, 100]
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Load all books initially
        with open(self.books_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                availability = "Available" if int(row['available_copies']) > 0 else "Not Available"
                tree.insert('', tk.END, values=(
                    row['book_id'], row['title'], row['author'],
                    row['publisher'], row['category'], 
                    row['available_copies'], availability
                ))
    
    def get_next_id(self, file_path, prefix):
        """Get next ID number for a given prefix"""
        max_id = 0
        try:
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    id_field = [k for k in row.keys() if 'id' in k.lower()][0]
                    id_num = int(row[id_field].replace(prefix, ''))
                    max_id = max(max_id, id_num)
        except (FileNotFoundError, IndexError, ValueError):
            pass
        return max_id + 1

    def search_online_books(self):
        """Search books from Open Library API and add to local library"""
        window = tk.Toplevel(self.root)
        window.title("Search Online Books")
        window.geometry("900x600")
        
        search_frame = tk.Frame(window, bg="#ecf0f1", pady=15)
        search_frame.pack(fill=tk.X, padx=10)
        
        tk.Label(search_frame, text="Search Title/Author:", font=("Arial", 11),
                 bg="#ecf0f1").pack(side=tk.LEFT, padx=5)
        search_entry = tk.Entry(search_frame, font=("Arial", 11), width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        tree_frame = tk.Frame(window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ('Title', 'Author', 'Year', 'ISBN', 'Add')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                            yscrollcommand=scrollbar.set)
        scrollbar.config(command=tree.yview)
        
        for col in columns[:-1]:
            tree.heading(col, text=col)
            tree.column(col, width=180)
        tree.heading('Add', text='Add')
        tree.column('Add', width=60)
        tree.pack(fill=tk.BOTH, expand=True)
        
        def search_books():
            query = search_entry.get().strip()
            for item in tree.get_children():
                tree.delete(item)
            if not query:
                return
            url = f"https://openlibrary.org/search.json?q={query}"
            try:
                resp = requests.get(url, timeout=10)
                data = resp.json()
                for doc in data.get('docs', [])[:30]:
                    title = doc.get('title', '')
                    author = ', '.join(doc.get('author_name', []))
                    year = doc.get('first_publish_year', '')
                    isbn = doc.get('isbn', [''])[0]
                    tree.insert('', tk.END, values=(title, author, year, isbn, 'Add'))
            except Exception as e:
                messagebox.showerror("Error", f"API error: {e}")
        
        def add_selected_book(event):
            item = tree.identify_row(event.y)
            if not item:
                return
            values = tree.item(item, 'values')
            book_id = f"BK{self.get_next_id(self.books_file, 'BK'):05d}"
            with open(self.books_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    book_id,
                    values[3],  # ISBN
                    values[0],  # Title
                    values[1],  # Author
                    '',         # Publisher (not available in API)
                    values[2],  # Year
                    '',         # Category (not available in API)
                    1,          # Total copies = 1
                    1           # Available copies = 1
                ])
            messagebox.showinfo("Success", "Book added to library!")
            # Optionally, refresh local book list or provide feedback
    
        tree.bind("<Button-1>", add_selected_book)
        
        tk.Button(search_frame, text="Search", command=search_books,
                 bg="#3498db", fg="white", font=("Arial", 10, "bold"),
                 padx=20).pack(side=tk.LEFT, padx=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = LibraryManagementSystem(root)
    root.mainloop()
