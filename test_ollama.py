import ollama

response = ollama.chat(
    model="llama3",
    messages=[
        {
            "role": "user",
            "content": "Say hello and tell me you are running locally."
        }
    ]
)

print(response["message"]["content"])