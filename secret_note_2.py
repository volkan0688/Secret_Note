from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_function():
    entry_title_user = entry_title.get()
    multiline_secret_user = multiline_secret.get("1.0", END)
    entry_key_user = entry_key.get()
    if entry_title_user == "" or multiline_secret_user == "" or entry_key_user == "":
        messagebox.showwarning(title="Hata!", message="Lütfen bütün alanları doldurun...")
    else:
        message_encoded = encode(entry_key_user, multiline_secret_user)
        try:
            with open("secret_note_2.txt", "a") as secret_file:
                secret_file.write(f"{entry_title_user}\n{message_encoded}\n")
        except:
            with open("secret_note_2.txt", "w") as secret_file:
                secret_file.write(f"{entry_title_user}\n{message_encoded}\n")
        finally:
            entry_title.delete(0,END)
            multiline_secret.delete("1.0",END)
            entry_key.delete(0,END)

def recyle_function():
    message_encoded = multiline_secret.get("1.0", END)
    entry_key_user = entry_key.get()
    if message_encoded == "" or entry_key_user == "":
        messagebox.showwarning(title="Hata!", message="Lütfen çözümlenecek bilgiyi ve parolanızı giriniz.")
    else:
        try:
            message_decoded = decode(entry_key_user, message_encoded)
            multiline_secret.delete("1.0",END)
            multiline_secret.insert("1.0",message_decoded)
        except:
            messagebox.showwarning(title="Hata!", message="Lütfen çözümlenecek bilgi giriniz.")

FONT1 = ('Helvetica', 16, 'italic')
FONT2 = ('Helvetica', 10, 'bold')
FONT3 = ('Helvetica', 14, 'italic')

window = Tk()
window.title("Secret Notes (by Volkan)")
window.minsize(width=425, height=900)
window.config(padx=20, pady=10, background="orange")

# Label Main Title
label_title = Label(text="SECRET NOTE", bg="orange", font=('Helvetica', 30, 'bold'), fg="white", padx=40, pady=20)
label_title.grid(row=1, column=0)

# Image
img_secret = PhotoImage(file="secret.png",)
img_label = Label(image=img_secret)
img_label.grid(row=2, column=0)

# Label Title
label_title = Label(text="Başlık giriniz:  ", bg="orange", font=FONT1, fg="black", padx=0, pady=10)
label_title.grid(row=3, column=0)

# Entry Title
entry_title = Entry(width=30, font=('Helvetica', 14, 'italic'), bg="powder blue")
entry_title.grid(row=4, column=0)
entry_title.focus()

# Label Secret
label_title = Label(text="Gizlemek istediğiniz bilgiyi giriniz:", bg="orange", font=FONT1, fg="black", padx=0, pady=10)
label_title.grid(row=5, column=0)

# Multiline Secret
multiline_secret = Text(width=35, height=15, bg="powder blue", font=FONT3)
multiline_secret.grid(row=6, column=0)

# Label Key
label_title = Label(text="Parolanızı giriniz:", bg="orange", font=FONT1, fg="black", padx=0, pady=10)
label_title.grid(row=7, column=0)

# Entry Key
entry_key = Entry(width=30, font=FONT1, bg="powder blue")
entry_key.grid(row=8, column=0)

# Button Save & Encrypt
encrypt_button = Button(text="Kaydet ve Şifrele", command=save_function, font=FONT2, bg="powder blue", padx=10, pady=3)
encrypt_button.place(x=120, y=800)

# Button Save & Decrypt
decrypt_button = Button(text="Şifreyi Çöz", command=recyle_function, font=FONT2, bg="powder blue", padx=10, pady=3)
decrypt_button.place(x=140, y=840)

window.mainloop()
