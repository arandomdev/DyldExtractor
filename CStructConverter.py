
FIELD_MAP = {
	"uint32_t": "c_uint32",
	"uint64_t": "c_uint64",
	"uint8_t": "c_uint8",

}

print("Paste the fields and then press enter twice")
fields: list[str] = []
fields.append(input())
while (True):
	line = input()
	if fields[-1] == "":
		del fields[-1]
		break

	fields.append(line)

for field in fields:
	field = field.replace("\t", " ")

	if "//" in field:
		field = field.partition("//")[0].strip()
	elif "/*" in field:
		field = field.partition("/*")[0].strip()

	fieldType = field[:field.index(" ")]
	field = field.replace(fieldType, "")
	if fieldType not in FIELD_MAP:
		print("Unknown field type: " + fieldType)
		continue
	fieldType = FIELD_MAP[fieldType]

	fieldName = field.strip().replace(";", "")

	print(f"(\"{fieldName}\", {fieldType}),")
	pass
