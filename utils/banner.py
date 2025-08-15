import time
from tqdm import tqdm

logo = r"""
                        ┏┓  •┏┏┏┓     
                        ┗┓┏┓┓╋╋┗┓┏┓┏  
                        ┗┛┛┗┗┛┛┗┛┗ ┗                                            \
                                                                                \ \
                                                                  __________.>))| |   Internet
[@] createor (👨‍💻 $ :-> Biswajit                               |              / /
[@] version  (🛠️    $ :->  1.0v                                  |              /
[@] git_hub  (🐙     $ :-> https://github.com/rout369            |
                                                                 |
  ___   _      ___   _      ___   _      ___   _      ___   _    |          
 [(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=|    [(_)] |=|   |
  '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_|     '-`  |_|   |
 /mmm/  /     /mmm/  /     /mmm/  /     /mmm/  /     /mmm/  /    |
       |____________|____________|____________|____________|_____|
                             |            |            |
                         ___  \_      ___  \_      ___  \_               
                        [(_)] |=|    [(_)] |=|    [(_)] |=|             
                         '-`  |_|     '-`  |_|     '-`  |_|              
                        /mmm/        /mmm/        /mmm/       
<<<<<<<<<<--------------------------------------------------------------------------------------->>>>>>>>>>                              
"""

# Show initial loading bar and logo
def show_initial_loading():
    for _ in tqdm(range(100), desc="Loading", ncols=100):
        time.sleep(0.02)  # Simulate loading time
    print(" ")
    print(logo)
    time.sleep(1)  # Brief delay
