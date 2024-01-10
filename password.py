from tkinter import *
import string
import random
import pyperclip


def generator():
    small_alphabets=string.ascii_lowercase
    capital_alphabets=string.ascii_uppercase
    numbers=string.digits
    special_charecters=string.punctuation

    all=small_alphabets+capital_alphabets+numbers+special_charecters
    password_length=int(length_Box.get())

    if choice.get()==1:
        passwordField.insert(0,random.sample(small_alphabets,password_length))

    if choice.get()==2:
        passwordField.insert(0,random.sample(small_alphabets+capital_alphabets,password_length))

    if choice.get()==3:
        passwordField.insert(0,random.sample(all,password_length))


def copy():
    random_password=passwordField.get()
    pyperclip.copy(random_password)

root=Tk()
root.title('Password Creator')
root.config(bg='cyan4')
root.geometry('400x500')
choice=IntVar()
Font=('arial',13,'bold')
passwordLabel=Label(root,text='Password Creator',font=('times new roman',20,'bold'),bg='cyan4',fg='white')
passwordLabel.grid(pady=10, padx=90)
easyradioButton=Radiobutton(root,text='Easy',value=1,variable=choice,font=Font, bg='darkgoldenrod1')
easyradioButton.grid(pady=10)

mediumradioButton=Radiobutton(root,text='Medium',value=2,variable=choice,font=Font, bg='darkgoldenrod1')
mediumradioButton.grid(pady=10)

complexradioButton=Radiobutton(root,text='Complex',value=3,variable=choice,font=Font, bg='darkgoldenrod1')
complexradioButton.grid(pady=10)

lengthLabel=Label(root,text='Password Length',font=Font,bg='cyan4',fg='white')
lengthLabel.grid(pady=20)

length_Box=Spinbox(root,from_=5,to_=18,width=5,font=Font)
length_Box.grid(pady=20)

generateButton=Button(root,text='Generate',font=Font,command=generator, bg='darkgoldenrod1')
generateButton.grid(pady=20)

passwordField=Entry(root,width=25,bd=2,font=Font)
passwordField.grid()

copyButton=Button(root,text='Copy',font=Font,command=copy, bg='darkgoldenrod1')
copyButton.grid(pady=20)

root.mainloop()