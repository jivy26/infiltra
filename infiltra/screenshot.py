# screenshot.py
import datetime
import os

from PIL import ImageGrab
import pyautogui


def take_screenshot(save_path="screenshots"):
    # Ensure the directory exists
    os.makedirs(save_path, exist_ok=True)

    # Generate a timestamped filename
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{timestamp}.png"
    file_path = os.path.join(save_path, filename)

    # Take a screenshot using pyautogui
    screenshot = pyautogui.screenshot()

    # Save the screenshot
    screenshot.save(file_path)
    print(f"Screenshot saved to {file_path}")
    return file_path
