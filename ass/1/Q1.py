
c = 'gighsqv wg o dipzwq ibwjsfgwhm tcibrsr wb hvs zigv vwzzg ct bobgvob \
rwghfwqh gvsbnvsb wh wg kcfywbu hckofrg psqcawbu o kcfzr qzogg ibwjsfgwhm slqszzwbu wb wbhsfrwgqwdzwbofm fsgsofqv bifhifwbu wbbcjohwjs \
hozsbhg obr rszwjsfwbu bsk ybckzsrus hc hvs kcfzr'
for k in range(0, 27):
    m = f'{k} '
    for i in c:
        if i == ' ':
            m += i
            continue
        m += chr(ord('a') + (ord(i) - ord('a') - k) % 26)
    print(m)
