"""Download the real NSL-KDD dataset (University of New Brunswick) from a public GitHub mirror."""
import urllib.request, pathlib
B = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
pathlib.Path("data").mkdir(exist_ok=True)
for f in ("KDDTrain%2B.txt", "KDDTest%2B.txt"):
    n = f.replace("%2B", "+"); print("downloading", n); urllib.request.urlretrieve(B + f, "data/" + n)
