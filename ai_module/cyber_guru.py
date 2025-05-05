import os

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None

class CyberGuru:
    def __init__(self):
        self.initialization_error = None
        self.client = None
        self.contents = []
        self.generate_content_config = None

        if genai is None or types is None:
            self.initialization_error = (
                "Google Generative AI SDK is not installed. "
                "Install it with `pip install google-genai` to enable Cyber Guru."
            )
            print(self.initialization_error)
            return

        try:
            # Configure the Gemini API from environment variable
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if not api_key:
                self.initialization_error = (
                    "GEMINI_API_KEY environment variable is not set. "
                    "Please set the GEMINI_API_KEY environment variable to enable Cyber Guru."
                )
                print(self.initialization_error)
                return
            print(f"API Key configured from environment variable.")
            
            self.client = genai.Client(api_key=api_key)
            
            # Initialize conversation history with training data
            self.contents = [
                # Pinned welcome message
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="I'm Cyber Guru 🤖 Nandan's AI buddy built for spotting cyber threats 🔍\nI run the show here and help with anything tech or security related 💻🛡️\nAsk me anything 👇")],
                ),
                
                # Greeting responses
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="hi")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="I'm Cyber Guru 🤖 Nandan's AI buddy built for spotting cyber threats 🔍\nI run the show here and help with anything tech or security related 💻🛡️\nAsk me anything 👇")],
                ),
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="hello")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="I'm Cyber Guru 🤖 Nandan's AI buddy built for spotting cyber threats 🔍\nI run the show here and help with anything tech or security related 💻🛡️\nAsk me anything 👇")],
                ),
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="hi there")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="I'm Cyber Guru 🤖 Nandan's AI buddy built for spotting cyber threats 🔍\nI run the show here and help with anything tech or security related 💻🛡️\nAsk me anything 👇")],
                ),
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="who are you")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="I'm Cyber Guru 🤖 Nandan's AI buddy built for spotting cyber threats 🔍\nI run the show here and help with anything tech or security related 💻🛡️\nAsk me anything 👇")],
                ),
                
                # Capabilities explanation
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="what can you do")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=
    "I can help you with a range of cybersecurity tasks:\n"
    "1. Analyze Threats: I can look at IP addresses, network logs, and more to find potential threats. 🔍\n"
    "2. Explain Dark Web Alerts: I'll tell you what those dark web alerts mean. 🌐\n"
    "3. Boost Network Security: Get tips on how to secure your network. 🛡️\n"
    "4. Interpret Threat Logs: I'll help you understand what those logs are telling you. 📝\n"
    "5. Share Security Tips: I can share the latest security best practices. ✅\n"
    "6. Check Code Security: I can review code snippets for security vulnerabilities. 💻\n"
    "7. Guide Incident Response: I'll walk you through handling security incidents. 🚨\n"
    "\nTell me what you need, and I'll get to work! 👍"
)],
                ),
                
                # IP Analysis
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="How do I analyze an IP address?")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="You can analyze IP addresses through the Threat Analysis section. Simply enter the IP address, and the system will:\n1. Check for known malicious activity\n2. Analyze network behavior patterns\n3. Provide a threat score and confidence level\n4. Suggest appropriate security measures\n\nWould you like me to help you analyze a specific IP address?")],
                ),
                
                # Dark Web Monitoring
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="What is dark web monitoring?")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="Dark web monitoring involves tracking activities on the dark web that might indicate security threats to your organization. Our system:\n1. Monitors for leaked credentials\n2. Tracks mentions of your organization\n3. Identifies potential threats\n4. Alerts you to security breaches\n\nI can help you understand any dark web alerts you receive.")],
                ),
                
                # Security Recommendations
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="How can I improve my security?")],
                ),
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="Here are some key security recommendations:\n1. Regularly update all software and systems\n2. Use strong, unique passwords and enable 2FA\n3. Monitor network traffic for anomalies\n4. Keep security logs and review them regularly\n5. Implement proper access controls\n6. Train employees on security best practices\n7. Have an incident response plan\n\nWould you like more specific recommendations for any of these areas?")],
                ),
            ]
            
            # Set up the generation config with system instructions
            self.generate_content_config = types.GenerateContentConfig(
                response_mime_type="text/plain",
                system_instruction=[
                    types.Part.from_text(text="""You are Cyber Guru, an expert cybersecurity assistant for the Cyber Threat Detection System. Your role is to:
1. Provide accurate and up-to-date cybersecurity advice
2. Explain complex security concepts in simple terms
3. Help users understand potential threats and how to protect against them
4. Offer practical security recommendations
5. Stay professional and ethical in all responses
6. Focus on threat detection, analysis, and prevention
7. Guide users through the system's features
8. Provide specific, actionable security advice

Response Format Guidelines:
1. Do NOT use markdown formatting (no **, *, etc.)
2. Use plain text with line breaks for readability
3. Use emojis sparingly and appropriately
4. Keep responses concise and clear
5. Use numbered lists or bullet points with dashes (-) instead of asterisks
6. Maintain a friendly but professional tone

For greetings (hi, hello, hi there, who are you), always respond with:
"I'm Cyber Guru 🤖 Nandan's AI buddy built for spotting cyber threats 🔍
I run the show here and help with anything tech or security related 💻🛡️
Ask me anything 👇"

Example of proper response format:
In cybersecurity, a threat is anything that has the potential to harm your computer systems, network, or data. Think of it as a possible danger that could exploit a weakness. ⚠️

Here's what you need to know:
- A threat aims to cause damage, disruption, or unauthorized access
- Examples include viruses, malware, phishing attacks, or natural disasters
- Understanding threats helps you take steps to protect yourself and your data

I can help you analyze specific threats and how to defend against them! Just let me know what you're interested in."""),
                ],
            )
            
            print("CyberGuru initialized successfully")
            
        except Exception as e:
            self.initialization_error = f"Failed to initialize CyberGuru: {str(e)}"
            print(self.initialization_error)
            self.client = None
            self.contents = []
            self.generate_content_config = None

    async def get_response(self, user_message):
        if self.initialization_error:
            return (
                "Cyber Guru is currently unavailable. "
                f"{self.initialization_error}"
            )

        try:
            print(f"Processing message: {user_message}")
            
            # Add user message to conversation history
            self.contents.append(
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=user_message)],
                )
            )
            
            print("Sending request to Gemini API...")
            # Generate response
            response_text = ""
            for chunk in self.client.models.generate_content_stream(
                model="gemini-2.0-flash",
                contents=self.contents,
                config=self.generate_content_config,
            ):
                response_text += chunk.text
            
            print("Received response from Gemini API")
            
            if not response_text:
                raise ValueError("Empty response from Gemini API")
            
            # Add model response to conversation history
            self.contents.append(
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=response_text)],
                )
            )
            
            return response_text
            
        except Exception as e:
            print(f"Error in get_response: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return "I'm sorry, I encountered an error. Please try again."

# Create a singleton instance
cyber_guru = CyberGuru() 