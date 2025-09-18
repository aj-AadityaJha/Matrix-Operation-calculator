import numpy as np
rows, cols = 3, 3

print(f"Enter the {rows*cols} elements of the {rows}x{cols} matrix (space-separated) e.g: 1 2 3 4...:")
elements = list(map(int, input().split())) #1st list, 2nd input, 3rd split convert "1,2" into '1','2'

# Convert the list to a NumPy array and reshape it
matrix = np.array(elements).reshape(rows, cols)

print("\nThe resulting matrix is:")
print(matrix)


print(f"Enter the {rows*cols} elements of the {rows}x{cols} 2nd matrix (space-separated) e.g: 1 2 3 4...:")
elements = list(map(int, input().split()))

# Convert the list to a NumPy array and reshape it
matrix1 = np.array(elements).reshape(rows, cols)

print("\nThe resulting matrix is:")
print(matrix1)

result = matrix + matrix1
print("Addition:")
print(result)

result2 = matrix @ matrix1
print("Multiplication:")
print(result2)

result3 = matrix - matrix1
print("Subtraction:")
print(result3)







