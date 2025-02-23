from Crypto.Util.number import * 
from secret import FLAG





n = bytes_to_long(FLAG)

initial_msg = "########################## Welcome To My Point Multiplier ###############################\n"+\
            ' Give me any point and I will multiply it using my secret key \n'+\
            'And since I am so generous here is my generator point : '



p = 1942668892225729070919461906823518906642406839052139521251812409738904285205208498723



class Point:
	def __init__(self,x,y,p=p):
		self.x = x % p
		self.y = y % p 
		self.modulus = p

def add(P,Q,p=p):
    if P.x == 0 and P.y == 0:
        return Q
    if Q.x == 0 and Q.y == 0:
        return P
    if P.x == Q.x and P.y == -Q.y:
        return Point(0,0)
    if P != Q:
        Lambda = (P.y - Q.y) * inverse(P.x - Q.x, p)
    else:
        Lambda = (3*(P.x**2) + 560069405746973935236942*P.x + 485862889966917787468710) * inverse(2*P.y + 310558460761504284968136, p)
    Lambda %= p
    R = Point(0,0)
    R.x = (Lambda**2 - P.x -Q.x - 280034702873486967618471 ) % p
    R.y = (Lambda*P.x - Lambda*R.x - P.y - 310558460761504284968136 ) % p
    return R

def multiply(P, n):
    Q = P
    R = Point(0, 0)
    while n > 0:
        if n % 2 == 1:
            R = add(R, Q)
        Q = add(Q, Q)
        n = n//2
    return R


def main():
    G = Point(229496382419185599708471019872976313780560290312527705689400770856463664989859774729,1840885465115874979229600066896274086403081644433321772728036680543517844131952062150)
    print(initial_msg)
    print((G.x,G.y))
    while True :
        print('\nWaiting For The Point .......')
        P = input('Enter Your Point:')
        try :
            P = P.strip("()").split(",")
            P = Point(int(P[0]),int(P[1]))
            nP = multiply(P,n)
            print("\nHere's The multiplication result:" , (nP.x,nP.y))
        except:
            print('something is wrong')


if __name__ == "__main__":
    main()

