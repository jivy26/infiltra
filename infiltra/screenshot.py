# screenshot.py

import os

from PIL import ImageGrab
import pyautogui


def take_screenshot(module_name, save_path="screenshots"):
    # Ensure the directory exists
    os.makedirs(save_path, exist_ok=True)

    filename = f"{module_name}.png"
    file_path = os.path.join(save_path, filename)

    screenshot = pyautogui.screenshot()

    screenshot.save(file_path)
    print(f"Screenshot saved to {file_path}")
    return file_path
