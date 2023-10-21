# Таймаут - параметр отвечающий за время ожидания загрузки веб-сайта, объясняя проще
# этот параметр задаёт количество времени которое программа будет ждать чтобы сайт загрузился
# если сайт в течении этого времени не загрузиться, то он будет считаться недоступным либо заблокированным.
# Стандартное значение Таймаута - 5 сек.
# Параметр очень важен, поскольку у разных операторов разная скорость интернета, вдруг идет проверка по 3г , где сайты в среднем грузяться 8 сек.

# Timeout - a parameter responsible for the time it takes to load a website, explaining in a simpler way
# this parameter sets the amount of time the program will wait for the site to load
# if the site does not load during this time, it will be considered inaccessible or blocked.
# Default value of Timeout is 5 sec.
# The parameter is very important, because different operators have different Internet speeds, for example if you check on 3g(h+) network, where sites load in 8 seconds in average.

timeout_cf_443 = 5
timeout_cf_80 = 5
timeout_fastly_443 = 5
timeout_fastly_80 = 5
timeout_azure_443 = 5
timeout_azure_80 = 5
timeout_cfront_443 = 5
timeout_cfront_80 = 5
timeout_arvan_443 = 5
timeout_arvan_80 = 5
timeout_verizon_443 = 5
timeout_verizon_80 = 5
timeout_gcore_443 = 5
timeout_gcore_80 = 5

