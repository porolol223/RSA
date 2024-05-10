import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")

        # Открытый текст
        self.plaintext_label = tk.Label(root, text="Открытый текст:")
        self.plaintext_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.plaintext_text = tk.Text(root, height=5, width=50)
        self.plaintext_text.grid(row=0, column=1, columnspan=2, padx=10, pady=5)

        # Кнопка для загрузки открытого текста
        self.load_plaintext_button = tk.Button(root, text="Загрузить", command=self.load_plaintext)
        self.load_plaintext_button.grid(row=0, column=3, padx=10, pady=5)

        # Публичный ключ (e, n)
        self.public_key_label = tk.Label(root, text="Публичный ключ (e, n) RSA:")
        self.public_key_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.public_key_text = tk.Text(root, height=2, width=50)
        self.public_key_text.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

        # Кнопка для загрузки публичного ключа
        self.load_public_key_button = tk.Button(root, text="Загрузить", command=self.load_public_key)
        self.load_public_key_button.grid(row=1, column=3, padx=10, pady=5)

        # Кнопка для вычисления ключей RSA
        self.generate_rsa_keys_button = tk.Button(root, text="Генерировать ключи RSA", command=self.generate_rsa_keys)
        self.generate_rsa_keys_button.grid(row=2, column=1, padx=10, pady=5)

        # Кнопка для шифрования
        self.encrypt_button = tk.Button(root, text="Зашифровать", command=self.encrypt)
        self.encrypt_button.grid(row=3, column=1, padx=10, pady=5)

        # Кнопка для дешифрования
        self.decrypt_button = tk.Button(root, text="Дешифровать", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=5)

    def load_plaintext(self):
        filename = filedialog.askopenfilename(initialdir="./", title="Выберите файл",
                                              filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename:
            with open(filename, "r") as file:
                self.plaintext_text.delete(1.0, tk.END)
                self.plaintext_text.insert(tk.END, file.read())

    def load_public_key(self):
        filename = filedialog.askopenfilename(initialdir="./", title="Выберите файл",
                                              filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if filename:
            with open(filename, "r") as file:
                self.public_key_text.delete(1.0, tk.END)
                self.public_key_text.insert(tk.END, file.read())

    def generate_rsa_keys(self):
        # Генерация ключей RSA
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Сохранение ключей в файлы
        filename_private = filedialog.asksaveasfilename(initialdir="./", title="Сохранить закрытый ключ RSA",
                                                        defaultextension=".pem",
                                                        filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if filename_private:
            with open(filename_private, "wb") as file:
                file.write(private_key)

        filename_public = filedialog.asksaveasfilename(initialdir="./", title="Сохранить открытый ключ RSA",
                                                       defaultextension=".pem",
                                                       filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if filename_public:
            with open(filename_public, "wb") as file:
                file.write(public_key)

        messagebox.showinfo("Успешно", "Сгенерированы ключи RSA и сохранены в файлы.")

    def encrypt(self):
        plaintext = self.plaintext_text.get(1.0, tk.END).strip().encode('utf-8')
        public_key = self.public_key_text.get(1.0, tk.END).strip()

        if not plaintext:
            messagebox.showerror("Ошибка", "Введите открытый текст")
            return
        if not public_key:
            messagebox.showerror("Ошибка", "Введите публичный ключ RSA")
            return

        # Шифрование с использованием асимметричного алгоритма RSA
        try:
            recipient_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            ciphertext_rsa = cipher_rsa.encrypt(plaintext)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании RSA: {str(e)}")
            return

        # Генерация случайного ключа и шифрование с использованием симметричного алгоритма DES
        des_key = os.urandom(8)
        cipher_des = DES.new(des_key, DES.MODE_ECB)
        ciphertext_des = cipher_des.encrypt(pad(plaintext, DES.block_size))

        # Сохранение зашифрованных данных в файлы
        filename_rsa = filedialog.asksaveasfilename(initialdir="./", title="Сохранить зашифрованный RSA текст",
                                                    defaultextension=".bin",
                                                    filetypes=(("Binary files", "*.bin"), ("All files", "*.*")))
        if filename_rsa:
            with open(filename_rsa, "wb") as file:
                file.write(ciphertext_rsa)

        filename_des = filedialog.asksaveasfilename(initialdir="./", title="Сохранить зашифрованный DES текст",
                                                    defaultextension=".bin",
                                                    filetypes=(("Binary files", "*.bin"), ("All files", "*.*")))
        if filename_des:
            with open(filename_des, "wb") as file:
                file.write(ciphertext_des)

        messagebox.showinfo("Успешно", "Шифрование завершено. Зашифрованные тексты сохранены.")

    def decrypt(self):
        # Загрузка зашифрованных данных из файлов
        filename_rsa = filedialog.askopenfilename(initialdir="./", title="Выберите файл с зашифрованным RSA текстом",
                                                  filetypes=(("Binary files", "*.bin"), ("All files", "*.*")))
        filename_des_key = filedialog.askopenfilename(initialdir="./", title="Выберите файл с зашифрованным ключом DES",
                                                      filetypes=(("Binary files", "*.bin"), ("All files", "*.*")))
        private_key = self.public_key_text.get(1.0, tk.END).strip()

        if not filename_rsa or not filename_des_key or not private_key:
            messagebox.showerror("Ошибка",
                                 "Выберите файлы с зашифрованным RSA текстом и ключом DES, а также введите секретный ключ RSA")
            return

        # Загрузка и дешифрование зашифрованного ключа DES с помощью RSA
        try:
            with open(filename_rsa, "rb") as file:
                ciphertext_rsa = file.read()
            with open(filename_des_key, "rb") as file:
                ciphertext_des_key = file.read()

            key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(key)
            des_key = cipher_rsa.decrypt(ciphertext_des_key)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при дешифровании ключа DES: {str(e)}")
            return

        # Дешифрование текста с помощью ключа DES
        try:
            cipher_des = DES.new(des_key, DES.MODE_ECB)
            with open(filename_des_key, "rb") as file:
                ciphertext_des = file.read()
            decrypted_text = unpad(cipher_des.decrypt(ciphertext_des), DES.block_size).decode('utf-8')
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при дешифровании текста DES: {str(e)}")
            return

        # Сохранение расшифрованного текста в файл
        filename_decrypted = filedialog.asksaveasfilename(initialdir="./", title="Сохранить расшифрованный текст",
                                                          filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename_decrypted:
            with open(filename_decrypted, "w") as file:
                file.write(decrypted_text)

        messagebox.showinfo("Успешно", "Дешифрование завершено. Расшифрованный текст сохранен.")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
