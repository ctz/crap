from results import first_char, samples

def mean(n):
    return sum(n) / len(n)
def bin(x, s):
    return s * int(x / s)

def output(samples, first_char, fn):
    with open(fn, 'w') as f:
        print >>f, 'set terminal pngcairo size 4096,4096'
        print >>f, 'set output "%s"' % (fn.replace('.gp', '.png'))
        print >>f, 'set key top left'
        print >>f, 'set boxwidth 0.05'
        for k, samps in samples.items():

            with open('res/%d.dat' % ord(k), 'w') as df:
                for i, d in enumerate(sorted(samps)):
                    print >>df, '%d %d' % (i, d)
        print >>f, 'plot', ', '.join("'res/%d.dat' u 1:2 pointsize 0.05 lc rgb '%s'" % (ord(k), ['#1100ff00', '#55ff0000'][k == first_char]) for k in [kk for kk in samples.keys() if kk != first_char] + [first_char])

print first_char
output(samples, first_char, 'graph.gp')

keys = samples.keys()
keys.sort(lambda x, y: cmp(mean(sorted(samples[x])[100:-1000]), mean(sorted(samples[y])[100:-1000])))

for k in keys:
    d = list(samples[k])
    d.sort()
    print k, len(d), mean(d), d[0], d[-1], mean(d[100:-1000])
