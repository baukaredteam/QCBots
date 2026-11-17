import pathlib
p = pathlib.Path(r'C:\Users\Бауыржан\Desktop\QC_Bots\backend\field_handlers.go')
t = p.read_text(encoding='utf-8')
t = t.replace('req.LogSourceTypeID', 'req.LogSourceID')
p.write_text(t, encoding='utf-8')
print('done')