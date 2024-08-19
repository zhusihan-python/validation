from rvalidate_extension import gen_validation, check_validation_py

if __name__ == "__main__":
    import os
    gen_validation(r"E:\projects\validation\src")
    res = check_validation_py(r"E:\projects\validation\src")
    print("res", res)
    print(os.path.dirname(__file__))