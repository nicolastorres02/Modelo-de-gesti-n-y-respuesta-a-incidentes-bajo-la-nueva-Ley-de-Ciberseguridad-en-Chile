import numpy as np
from scipy import stats

modelo = [3.9, 6.8, 14.2, 6.8, 31.6, 9.2, 8.6, 22.6, 9.3, 11.6, 7.6, 14.3, 8.6, 16.2, 2.5]
base   = [25, 23, 26, 15, 37, 27, 23, 36, 30, 15, 30, 30, 18, 26, 31]

def desc(x):
    x=np.array(x,float)
    return dict(n=len(x), mediana=np.median(x), q1=np.percentile(x,25),
                q3=np.percentile(x,75), minimo=x.min(), maximo=x.max(),
                media=x.mean(), sd=x.std(ddof=1))

dm, db = desc(modelo), desc(base)
print("=== DESCRIPTIVA TTC (segundos) ===")
for nom,d in [("MODELO",dm),("BASE",db)]:
    print(f"{nom}: n={d['n']}  mediana={d['mediana']:.1f}  IQR=[{d['q1']:.1f}-{d['q3']:.1f}]  "
          f"min={d['minimo']:.1f}  max={d['maximo']:.1f}  media={d['media']:.2f}  sd={d['sd']:.2f}")

# Mann-Whitney: H1 -> modelo < base (modelo contiene mas rapido)
U, p = stats.mannwhitneyu(modelo, base, alternative='less')
n1, n2 = len(modelo), len(base)
# rank-biserial effect size
r_rb = 1 - (2*U)/(n1*n2)
# Cliff's delta
def cliffs(a,b):
    a,b=np.array(a),np.array(b); gt=lt=0
    for x in a:
        gt+=np.sum(x>b); lt+=np.sum(x<b)
    return (gt-lt)/(len(a)*len(b))
d_cliff = cliffs(modelo, base)
print("\n=== MANN-WHITNEY U (unilateral, H1: modelo < base) ===")
print(f"U={U:.1f}  p={p:.6g}")
print(f"rank-biserial r={r_rb:.3f}")
print(f"Cliff's delta={d_cliff:.3f}")
red = (1 - dm['mediana']/db['mediana'])*100
print(f"\nReduccion de la mediana del TTC: {red:.1f}%  ({db['mediana']:.1f}s -> {dm['mediana']:.1f}s)")
