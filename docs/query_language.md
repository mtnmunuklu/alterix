## Shortcuts
- `<enter>`: Arama yapmak için
- `<ctrl>+<space>`: Önerileri görmek için
- `<shift>+<enter>`: Yeni satır eklemek için

## Examples
- **source**
    - `source | select | where | limit | order by | group | '|'external functions`
    - `source in ('13151', '13158')`
    - `source in ('Microsoft Security', 'Palo Alto')`
    - `source like 'Microsoft Secu%'`
    - `source = 'Microsoft Security'`
    - `sourcetype = 'Security'`
    - `sourcetag = 'SourceTag'`
    - `select *` (tüm sütunları ve satırları döndürür)
    - `select col1, col2` (seçilen sütun değerlerini döndürür)
    - `where 'palo alto'` (tam metin araması yapar)
    - `where col1 > 20 or (col2 = 'palo' and col3 != 'host')` (birden çok koşullu ifade)
    - `where col1 between 123 and 456`
    - `select col1, col2 group`
    - `select col1, col2, count(*) group having count(*) > 20`
    - `select col1, col2 order by col1 asc, col2 desc`

- **select**
    - 'select' komutuyla alınacak sütun adları belirtilir
    - `select [*|columns...|aggregation functions...|as]`

- **where**
    - Kayıtları filtrelemek için kullanılır
    - Operatörler: `=`, `!=`, `>`, `<`, `>=`, `<=`, `between`, `in`, `notin`, `like`, `notlike`

- **group**
    - Bir veya daha fazla sütuna göre sonuç kümesini gruplar
    - `select [group columns..., aggregation functions...] group [group columns] having [group conditional expression] top [number]`

- **Aggregation Functions**
    - `count`, `sum`, `avg`, `min`, `max`

- **order by**
    - Sütunları artan veya azalan sıraya göre sıralamak için kullanılır
    - `select [columns...] order by [columns...] [asc|desc]`

- **limit**
    - Sonuç kümesini sınırlar
    - `limit [number]`

- **External Functions**
    - Pipe (|) karakterinden sonra sistemde yüklenen harici fonksiyonlar kullanılabilir

- **uniq**
    - Sonucu gruplar ve 'count' sütunu ekler

- **head**
    - Sonucun ilk N satırını döndürür

- **eval**
    - Seçilen sütunda verilen ifadeyi çalıştırır

- **regex**
    - Verilen düzenli ifadeyle eşleşenleri alır

- **top**
    - Verilen sütun için en üst N değeri alır

- **rename**
    - Sütunları yeniden adlandırır

- **linecount**
    - Satır sayısını içeren bir sütun ve değer döndürür

- **sum**
    - Her sütunun toplamını döndürür

- **avg**
    - Her sütunun ortalamasını döndürür

- **min**
    - Her sütunun minimumunu döndürür

- **max**
    - Her sütunun maksimumunu döndürür

- **count**
    - Her sütunun sayısını döndürür

- **std**
    - Her sütunun standart sapmasını döndürür