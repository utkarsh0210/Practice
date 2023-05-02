import pyttsx3
import datetime
import speech_recognition as sr
import wikipedia
import webbrowser
import os
import smtplib
import ecapture
import ecapture as ec
import pyaudio
import csv
engine = pyttsx3.init('sapi5')
voices=engine.getProperty('voices')
#print(voices[1].id)
engine.setProperty('voice',voices[1].id)



def speak(audio):
    engine.say(audio)
    engine.runAndWait()

def wishMe():
    hour = int(datetime.datetime.now().hour)
    if hour>=0 and hour<12:
        speak("good morning")

    elif hour>=12 and hour<18:
        speak("good afternoon")

    else:
        speak("good evening")

    speak("I am Jarvis , plese tell me how may I help you")

def takeCommand():
    #it takes input from microphone and returns a string output
    r=sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        r.pause_threshold = 1
        audio = r.listen(source)

    try:
        print("recognizing...")
        query = r.recognize_google(audio, language='en-in')
        print(f"User said: {query}\n")

    except Exception as e:
        print(e)   

        print("Say that again please...")
        return "none"
    return query

if __name__ == "__main__":
    wishMe()
    while True:
        query = takeCommand().lower()

    # logic for executing tasks based on query
        if 'wikipedia' in query:
            speak("Searching wikipedia...")
            query = query.replace("wikipedia", "")
            results = wikipedia.summary(query, sentences=2)
            speak("according to wikipedia")
            print(results)
            speak(results)
            #i=i+1

        elif 'open youtube' in query:
            webbrowser.open("youtube.com")
            #i=i+1

        elif 'open google' in query:
            webbrowser.open("google.com")
            #i=i+1

        elif 'open chatGPT' in query:
            webbrowser.open("https:\\//chat.openai.com\/chat")

        elif 'open stack overflow' in query:
            webbrowser.open("stackoverflow.com")
            i=i+1

        elif 'open github' in query:
            webbrowser.open("github.com")
            #i=i+1

        elif 'open webkiosk' in query:
            webbrowser.open("webkiosk.juet.ac.in")
            #i=i+1

        

        elif 'the time' in query:
            strTime = datetime.datetime.now().strftime("%H:%M:%S")
            speak(f"the time is{strTime}")
            #i=i+1

        elif 'open code' in query:
            codePath = "C:\\Users\\utkun\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"
            os.startfile(codePath)
            #i=i+1

        elif 'camera' in query or 'photo' in query:
            ec.capture(0, "jarvis camera","img.jpg")
            i=i+1

        elif 'open notes' in query:
            speak("what should i write sir")
            note = takeCommand()
            file = open('jarvis.txt', 'w')
            file.write(note)
            #i=i+1

        elif "don't listen" in query or "stop listening" in query:
            speak("for how much time you want to stop jarvis")
            a = int(takeCommand())
            datetime.sleep(a)
            print(a)
            #i=i+1


        #elif 'is love' in query:
           # speak("It is 7th sense that destroy all other senses")
            #i=i+1

        elif 'open snipping tool' in query:
            snip_tool = open("%windir%\\system32\\SnippingTool.exe")
            #i=i+1

        elif 'open whatsapp' in query:
            what_sapp = open("C:\\Users\\utkun\\AppData\\Local\\WhatsApp\\WhatsApp.exe")
            what_sapp=csv.reader(what_sapp)
            #i=i+1

        elif 'open linkedin' in query:
            webbrowser.open("www.linkedin.com")
            
        elif 'quit' in query:
            exit()
            #i=i+1