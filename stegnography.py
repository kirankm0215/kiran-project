import cv2
import numpy as np
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

def generate_key(password):
    key = hashlib.sha256(password.encode()).digest()  
    return base64.urlsafe_b64encode(key[:32])  


def encrypt_message(message, password):
    key = generate_key(password)
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message.decode()  

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    cipher = Fernet(key)
    try:
        decrypted_message = cipher.decrypt(encrypted_message.encode()).decode()
        return decrypted_message
    except:
        return "Invalid Password!"


def encode_image(image_path, secret_text, password, output_path):
    img = cv2.imread(image_path)
    height, width, _ = img.shape

    
    encrypted_text = encrypt_message(secret_text, password)

    
    binary_message = ''.join(format(ord(char), '08b') for char in encrypted_text)
    binary_message += "1111111111111110"  

    
    data_index = 0
    total_pixels = height * width * 3  
    if len(binary_message) > total_pixels:
        messagebox.showerror("Error", "Message too long for the image!")
        return False

    for row in img:
        for pixel in row:
            for i in range(3): 
                if data_index < len(binary_message):
                    pixel[i] = (pixel[i] & 254) | int(binary_message[data_index])
                    data_index += 1
                else:
                    break

    
    cv2.imwrite(output_path, img)
    return True


def decode_image(image_path, password):
    img = cv2.imread(image_path)
    binary_message = ""

    for row in img:
        for pixel in row:
            for i in range(3):  
                binary_message += str(pixel[i] & 1) 

    
    binary_message = binary_message.split("1111111111111110")[0]

    
    encrypted_message = ""
    for i in range(0, len(binary_message), 8):
        char = chr(int(binary_message[i:i+8], 2))
        encrypted_message += char

    
    return decrypt_message(encrypted_message, password)


def open_file():
    file_path = filedialog.askopenfilename()
    return file_path


def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".png",
                                             filetypes=[("PNG files", "*.png"), ("All Files", "*.*")])
    return file_path


def encode_message():
    img_path = open_file()
    if not img_path:
        return
    
    secret_text = message_entry.get()
    password = password_entry.get()
    if not secret_text or not password:
        messagebox.showerror("Error", "Enter both message and password!")
        return

    output_path = save_file()
    if not output_path:
        return

    if encode_image(img_path, secret_text, password, output_path):
        messagebox.showinfo("Success", "Message successfully hidden in image!")


def decode_message():
    img_path = open_file()
    if not img_path:
        return
    
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Enter the password!")
        return

    message = decode_image(img_path, password)
    messagebox.showinfo("Decoded Message", message)


def on_hover(event, widget):
    widget.configure(bg="#004d99", fg="white")

def on_leave(event, widget):
    widget.configure(bg="#007bff", fg="white")


root = tk.Tk()
root.title("Secure Image Steganography")
root.geometry("450x400")
root.resizable(False, False)
root.configure(bg="#f0f0f0")


header_frame = tk.Frame(root, bg="#007bff", height=60)
header_frame.pack(fill="x")

header_label = tk.Label(header_frame, text="🔒 Secure Image Steganography", font=("Arial", 16, "bold"), fg="white", bg="#007bff")
header_label.pack(pady=10)


content_frame = tk.Frame(root, bg="#f0f0f0")
content_frame.pack(pady=20)


message_label = tk.Label(content_frame, text="Enter Secret Message:", font=("Arial", 12, "bold"), bg="#f0f0f0")
message_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)
message_entry = tk.Entry(content_frame, width=40, font=("Arial", 12))
message_entry.grid(row=0, column=1, padx=10, pady=5)


password_label = tk.Label(content_frame, text="Enter Password:", font=("Arial", 12, "bold"), bg="#f0f0f0")
password_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)
password_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), show="*")
password_entry.grid(row=1, column=1, padx=10, pady=5)


button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.pack(pady=20)


encode_button = tk.Button(button_frame, text="🔐 Encode Message", font=("Arial", 12, "bold"), bg="#007bff", fg="white", padx=20, pady=5, command=encode_message)
encode_button.grid(row=0, column=0, padx=10, pady=5)


decode_button = tk.Button(button_frame, text="🔓 Decode Message", font=("Arial", 12, "bold"), bg="#007bff", fg="white", padx=20, pady=5, command=decode_message)
decode_button.grid(row=0, column=1, padx=10, pady=5)


encode_button.bind("<Enter>", lambda event: on_hover(event, encode_button))
encode_button.bind("<Leave>", lambda event: on_leave(event, encode_button))

decode_button.bind("<Enter>", lambda event: on_hover(event, decode_button))
decode_button.bind("<Leave>", lambda event: on_leave(event, decode_button))


root.mainloop()
