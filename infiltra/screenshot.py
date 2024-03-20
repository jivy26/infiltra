# screenshot.py
import datetime
import time
import os

from PIL import ImageGrab
import pyautogui


def take_screenshot(module_name, save_path="screenshots"):
    # Ensure the directory exists
    os.makedirs(save_path, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{module_name}_{timestamp}.png"
    file_path = os.path.join(save_path, filename)

    time.sleep(1)
    screenshot = pyautogui.screenshot()

    screenshot.save(file_path)
    print(f"Screenshot saved to {file_path}")
    return file_path
