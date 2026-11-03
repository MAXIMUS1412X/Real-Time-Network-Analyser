"""DAA algorithms that operate on captured packet dictionaries."""

def linear_search(records, field, target):
    target = str(target).strip().lower()
    for i, record in enumerate(records):
        if str(record.get(field, "")).lower() == target:
            return i
    return -1


def binary_search(sorted_records, field, target):
    """O(log n); records must already be sorted by the selected field."""
    target = str(target).strip().lower()
    low, high = 0, len(sorted_records) - 1
    while low <= high:
        mid = (low + high) // 2
        value = str(sorted_records[mid].get(field, "")).lower()
        if value == target:
            return mid
        if value < target:
            low = mid + 1
        else:
            high = mid - 1
    return -1


def bubble_sort(records, field):
    arr = list(records)
    for i in range(len(arr)):
        swapped = False
        for j in range(0, len(arr) - i - 1):
            if arr[j].get(field) > arr[j + 1].get(field):
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
                swapped = True
        if not swapped:
            break
    return arr


def quick_sort(records, field):
    arr = list(records)
    def sort(low, high):
        i, j = low, high
        pivot = arr[(low + high) // 2].get(field)
        while i <= j:
            while arr[i].get(field) < pivot:
                i += 1
            while arr[j].get(field) > pivot:
                j -= 1
            if i <= j:
                arr[i], arr[j] = arr[j], arr[i]
                i += 1
                j -= 1
        if low < j:
            sort(low, j)
        if i < high:
            sort(i, high)
    if len(arr) > 1:
        sort(0, len(arr) - 1)
    return arr


def merge_sort(records, field):
    if len(records) <= 1:
        return list(records)
    mid = len(records) // 2
    left = merge_sort(records[:mid], field)
    right = merge_sort(records[mid:], field)
    result, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        if left[i].get(field) <= right[j].get(field):
            result.append(left[i]); i += 1
        else:
            result.append(right[j]); j += 1
    result.extend(left[i:]); result.extend(right[j:])
    return result
