import matplotlib.pyplot as plt
import sys
import pandas as pd

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Usage: python plotting.py <parsed csv file> <optional:vendor name> ")
    sys.exit(1)
file = sys.argv[1]

#Reads all engine times to a list
day = 60 * 60 * 24
engine_times = []
with open(file, "r") as outputs:
    df = pd.read_csv(outputs)
    for i, engine_time in enumerate(df['Engine Time']):
        if (len(sys.argv) == 2 or df['Vendor'][i] == sys.argv[2]):
            engine_times.append(int(int(engine_time)/day))

if (len(sys.argv) == 3):
    #Plot for chosen vendor
    plt.title   ('Server Counts per Last Reboot Time from ' + sys.argv[2])
else: 
    #Plot for all vendors
    plt.title   ('Server Counts per Last Reboot Time')

#Plots engine times as a histogram
plt.xlabel  ('Days Since Reboot')
plt.ylabel  ('Number of servers')
plt.hist(engine_times, range=(0,365*2), bins=20)
plt.show()
