#!/usr/bin/python3

import random
import os 
from Crypto.Util.number import bytes_to_long
from secret import FLAG

before_message = '''
   ____    ___  ___  _______    _______  ___________  
  /  " \  |"  \/"  ||   _  "\  /"     "|("     _   ") 
 /__|| |   \   \  / (. |_)  :)(: ______) )__/  \\__/  
    |: |    \\  \/  |:     \/  \/    |      \\_ /     
   _\  |    /\.  \  (|  _  \\  // ___)_     |.  |     
  /" \_|\  /  \   \ |: |_)  :)(:      "|    \:  |     
 (_______)|___/\___|(_______/  \_______)     \__|     
                                                      
'''

class RouletteGame:
    def __init__(self, seed , total_rounds=1000):
        self.total_rounds = total_rounds
        self.current_round = 0
        self.numbers = []
        random.seed(seed)  
        for _ in range(total_rounds):
            self.numbers.append(random.getrandbits(32))
    def preview_numbers(self):
        indices_input = input("Enter up to 6 comma-separated indices to preview (e.g., 0,10,100): ")
        try:
            indices = [int(index.strip()) for index in indices_input.split(",")]
            if len(indices) > 6:
                print("You can only preview up to 6 indices.")
                exit()
        except ValueError:
            print("Invalid input.")
            exit()

        print("Preview of specific indices:")
        for index in indices:
            if 0 <= index < self.total_rounds:
                print(f"Index {index}: {self.numbers[index]}")
            else:
                print(f"Index {index} is out of range.")

    def play_round(self):
            self.current_round += 1
            print(f"Round {self.current_round}")
            try:
                user_guess = int(input("Guess the number: "))
            except ValueError:
                print("Invalid input.")
                self.current_round -= 1  
                exit()
                

            winning_number = self.numbers[self.current_round - 1]

            if user_guess == winning_number  :
                if self.current_round <= self.total_rounds - 1:
                    print("Correct! Moving to the next round.\n")
                elif self.current_round == self.total_rounds :
                    print("u beated the house congrats !!! ")
                    print(f"here is your flag : {FLAG}")
            else:
                print("Wrong guess! You lose. Game over.")
                exit()
            
print(before_message)
game = RouletteGame(bytes_to_long(os.urandom(4)))
game.preview_numbers()

while game.current_round < game.total_rounds:
    game.play_round()


