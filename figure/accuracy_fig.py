import matplotlib.pyplot as plt

# Similarity Threshold
threshold = []
i = 1
while i < 10:
    threshold.append(i / 10)
    i += 1

# Accuracy Score
accuracy = [1.0, 1.0, 1.0, 1.0, 0.9993609640314041, 0.9981741829468688, 0.9829286105532226, 0.8362242103341245, 0.5271133832389995]

plt.plot(threshold, accuracy, 'o-r')
plt.title("SymLM Function Name Prediction Accuracy for Linux Binaries")
plt.ylabel('Accuracy (%)')
plt.xlabel('Simlarity Threshold')
plt.show()
