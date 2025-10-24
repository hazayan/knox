package dbus

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

func TestValidateLabel(t *testing.T) {
	tests := []struct {
		name      string
		label     string
		wantValid bool
	}{
		{"Valid label", "My Secret Label", true},
		{"Empty label", "", true},
		{"Long label", "This is a very long label that should still be valid", true},
		{"Special chars", "Label with !@#$%^&*()", true},
		{"Unicode", "Label with emoji 🚀", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLabel(tt.label)
			if tt.wantValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateCollectionName(t *testing.T) {
	tests := []struct {
		name      string
		colName   string
		wantValid bool
	}{
		{"Valid name", "my-collection", true},
		{"Valid with underscore", "my_collection", true},
		{"Valid with numbers", "collection123", true},
		{"Valid mixed case", "MyCollection", true},
		{"Empty name", "", false},
		{"Invalid slash", "collection/name", false},
		{"Invalid backslash", "collection\\name", false},
		{"Invalid colon", "collection:name", false},
		{"Invalid pipe", "collection|name", false},
		{"Invalid asterisk", "collection*name", false},
		{"Invalid question mark", "collection?name", false},
		{"Invalid double quote", "collection\"name", false},
		{"Invalid single quote", "collection'name", false},
		{"Invalid angle brackets", "collection<name", false},
		{"Invalid brackets", "collection[name", false},
		{"Invalid braces", "collection{name", false},
		{"Invalid percent", "collection%name", false},
		{"Invalid ampersand", "collection&name", false},
		{"Invalid equals", "collection=name", false},
		{"Invalid plus", "collection+name", false},
		{"Invalid comma", "collection,name", false},
		{"Invalid semicolon", "collection;name", false},
		{"Invalid space", "collection name", false},
		{"Invalid tab", "collection\tname", false},
		{"Invalid newline", "collection\nname", false},
		{"Invalid carriage return", "collection\rname", false},
		{"Invalid null byte", "collection\x00name", false},
		{"Too long", "this-collection-name-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-this-collection-name-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-this-collection-name-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-this-collection-name-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCollectionName(tt.colName)
			if tt.wantValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateItemID(t *testing.T) {
	tests := []struct {
		name      string
		itemID    string
		wantValid bool
	}{
		{"Valid ID", "item-123", true},
		{"Valid with underscore", "item_123", true},
		{"Valid with numbers", "123item", true},
		{"Valid UUID", "550e8400-e29b-41d4-a716-446655440000", true},
		{"Empty ID", "", false},
		{"Invalid slash", "item/123", false},
		{"Invalid backslash", "item\\123", false},
		{"Invalid colon", "item:123", false},
		{"Invalid pipe", "item|123", false},
		{"Invalid asterisk", "item*123", false},
		{"Invalid question mark", "item?123", false},
		{"Invalid double quote", "item\"123", false},
		{"Invalid single quote", "item'123", false},
		{"Invalid angle brackets", "item<123", false},
		{"Invalid brackets", "item[123", false},
		{"Invalid braces", "item{123", false},
		{"Invalid percent", "item%123", false},
		{"Invalid ampersand", "item&123", false},
		{"Invalid equals", "item=123", false},
		{"Invalid plus", "item+123", false},
		{"Invalid comma", "item,123", false},
		{"Invalid semicolon", "item;123", false},
		{"Invalid space", "item 123", false},
		{"Invalid tab", "item\t123", false},
		{"Invalid newline", "item\n123", false},
		{"Invalid carriage return", "item\r123", false},
		{"Invalid null byte", "item\x00123", false},
		{"Too long", "this-item-id-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-item-identifier-in-the-system-this-item-id-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-item-identifier-in-the-system-this-item-id-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-item-identifier-in-the-system", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateItemID(tt.itemID)
			if tt.wantValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateAttributes(t *testing.T) {
	tests := []struct {
		name       string
		attributes map[string]string
		wantValid  bool
	}{
		{"Valid attributes", map[string]string{"app": "firefox", "url": "example.com"}, true},
		{"Empty attributes", map[string]string{}, true},
		{"Valid with special chars", map[string]string{"app.name": "my-app", "url.path": "/secret"}, true},
		{"Valid unicode", map[string]string{"emoji": "🚀", "description": "rocket secret"}, true},
		{"Key too long", map[string]string{"this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key-this-key-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-key": "value"}, false},
		{"Value too long", map[string]string{"key": "this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems-this-value-is-way-too-long-and-should-be-rejected-because-it-exceeds-reasonable-length-limits-for-an-attribute-value-in-the-system-which-might-cause-performance-issues-or-other-problems"}, false},
		{"Too many attributes", map[string]string{
			"key1": "value1", "key2": "value2", "key3": "value3", "key4": "value4", "key5": "value5",
			"key6": "value6", "key7": "value7", "key8": "value8", "key9": "value9", "key10": "value10",
			"key11": "value11", "key12": "value12", "key13": "value13", "key14": "value14", "key15": "value15",
			"key16": "value16", "key17": "value17", "key18": "value18", "key19": "value19", "key20": "value20",
			"key21": "value21", "key22": "value22", "key23": "value23", "key24": "value24", "key25": "value25",
			"key26": "value26", "key27": "value27", "key28": "value28", "key29": "value29", "key30": "value30",
			"key31": "value31", "key32": "value32", "key33": "value33", "key34": "value34", "key35": "value35",
			"key36": "value36", "key37": "value37", "key38": "value38", "key39": "value39", "key40": "value40",
			"key41": "value41", "key42": "value42", "key43": "value43", "key44": "value44", "key45": "value45",
			"key46": "value46", "key47": "value47", "key48": "value48", "key49": "value49", "key50": "value50",
			"key51": "value51", "key52": "value52", "key53": "value53", "key54": "value54", "key55": "value55",
			"key56": "value56", "key57": "value57", "key58": "value58", "key59": "value59", "key60": "value60",
			"key61": "value61", "key62": "value62", "key63": "value63", "key64": "value64", "key65": "value65",
			"key66": "value66", "key67": "value67", "key68": "value68", "key69": "value69", "key70": "value70",
			"key71": "value71", "key72": "value72", "key73": "value73", "key74": "value74", "key75": "value75",
			"key76": "value76", "key77": "value77", "key78": "value78", "key79": "value79", "key80": "value80",
			"key81": "value81", "key82": "value82", "key83": "value83", "key84": "value84", "key85": "value85",
			"key86": "value86", "key87": "value87", "key88": "value88", "key89": "value89", "key90": "value90",
			"key91": "value91", "key92": "value92", "key93": "value93", "key94": "value94", "key95": "value95",
			"key96": "value96", "key97": "value97", "key98": "value98", "key99": "value99", "key100": "value100",
			"key101": "value101",
		}, false},
		{"Invalid key characters", map[string]string{"key\nwith": "newline"}, false},
		{"Invalid value characters", map[string]string{"key": "value\nwith"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAttributes(tt.attributes)
			if tt.wantValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateSessionPath(t *testing.T) {
	tests := []struct {
		name      string
		path      dbus.ObjectPath
		wantValid bool
	}{
		{"Valid session path", "/org/freedesktop/secrets/session/abc123", true},
		{"Invalid prefix", "/wrong/prefix/session/abc123", false},
		{"Missing session ID", "/org/freedesktop/secrets/session/", false},
		{"Empty path", "", false},
		{"Root path", "/", false},
		{"Invalid characters", "/org/freedesktop/secrets/session/../..", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSessionPath(tt.path)
			if tt.wantValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateCollectionPath(t *testing.T) {
	tests := []struct {
		name      string
		path      dbus.ObjectPath
		wantValid bool
	}{
		{"Valid collection path", "/org/freedesktop/secrets/collection/default", true},
		{"Valid custom collection", "/org/freedesktop/secrets/collection/my-collection", true},
		{"Invalid prefix", "/wrong/prefix/collection/default", false},
		{"Missing collection name", "/org/freedesktop/secrets/collection/", false},
		{"Empty path", "", false},
		{"Root path", "/", false},
		{"Invalid characters", "/org/freedesktop/secrets/collection/../..", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCollectionPath(tt.path)
			if tt.wantValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
