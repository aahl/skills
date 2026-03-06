# Sent message content

https://open.larksuite.com/document/server-docs/im-v1/message-content-description/create_json?lang=en-US
Last updated on 2024-11-18

This document explains **how to construct the "content" field for each message type** in the [Send message](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create), [Reply message](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/reply) and [Edit message](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/update) APIs.
- In the sample code in this document, all receive_id, user_id, image_key, and file_key values are example values, and developers need to replace them in actual use.
- The content construction example of this article is only applicable to the new version [Send Message](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create), [Reply message](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/reply) and [Edit message](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/update) APIs, **not applicable to [Send messages in batches](https://open.larksuite.com/document/ukTMukTMukTM/ucDO1EjL3gTNx4yN4UTM) and Historical Version APIs.**
- This article does not apply to custom bots. For custom robots, please refer to [Custom bot usage guide](https://open.larksuite.com/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN).

## Request body example
Content is of the **string** type, and the JSON structure needs to be escaped.

By using a text-type message as an example, the request body example is as follows:
```json 
{
    "receive_id": "ou_7d8a6e6df7621556ce0d21922b676706ccs",
    "content": "{\"text\":\" test content\"}",
    "msg_type": "text"
}
``` 

## JSON structures for different message types

### Text

```json 
{
    "text": "test content"
}
``` 

**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| text | string | Yes | text content | none | test content |

**Message-sending Request Body Example**
```json 
{
    "receive_id": "ou_7d8a6e6df7621556ce0d21922b676706ccs",
    "content": "{\"text\":\"test content\"}",
    "msg_type": "text"
}
``` 

**Instructions on Line Break Usage**
To break a line in the text, you must add escaping

```json 
{
    "receive_id": "oc_xxx",
    "content": "{\"text\":\"firstline \\n second line\"}",
    "msg_type": "text"
}
``` 

**Instructions on Text-message @mentioning Usage**
- When @mentioning a specific user, should enter open_id, union_id or user_id in `user_id` field. The value must be valid. Please refer to [How to get User ID, Open ID and UnionID?](https://open.larksuite.com/document/home/user-identity-introduction/open-id) for ID acquisition.
- When @mentioning all users, @mention all function must be enabled for the group. 
- The syntax here is different from that of the message card [Markdown module](https://open.larksuite.com/document/ukTMukTMukTM/uADOwUjLwgDM14CM4ATN#abc9b025) @specified person, please pay attention to the distinction.

```
 // @Mention a single user
<at user_id="ou_xxx">user name(optional)</at>
// @Mention all users
<at user_id="all"></at>
``` 
**Example**
```json 
{
    "receive_id": "oc_xxx",
    "content": "{\"text\":\"<at user_id=\\\"ou_xxx\\\">Tom</at> text content\"}",
    "msg_type": "text"
} 
```

**Instructions on Text Style Tags Usage**
- Four styles are supported: bold, italic, underline, and strikethrough, which can be nested:
  - **Bold**: **Text Example**
  - *Italic*: <i>Text Example</i>
  -  _Underline_ : <u>Text Example</u>
  - ~~Strikeline~~: <s>Text Example</s>
- Please ensure that the first and last tags correspond and the nesting is correct. If the first and last tags are missing, the nesting level is wrong, etc., the message will be sent with the original content.
- Label information will greatly increase the size of the message body, please use it as appropriate.
- This capability **does not support** custom bots and [sending messages in batches](https://open.larksuite.com/document/ukTMukTMukTM/ucDO1EjL3gTNx4yN4UTM) API currently.

**Example**
```json
{
    "receive_id": "oc_xxx",
    "content": "{\"text\":\"**bold content<i>, bold and italic content</i>**\"}",
    "msg_type": "text"
}
```

**Instructions on Hyperlink Usage**
- The hyperlink format is `[text](link)`, such as `[Lark Open Platform(https://open.larksuite.com)`.
- [] multi-level nesting is not supported in `[text]`; In addition, if the text contains other '[' or ']' characters, please ensure that the front and back symbols match, otherwise it may cause hyperlink recognition exception.
- Please make sure the link is legitimate, otherwise the message will be sent with the original content.
- This capability **does not support** custom bots and [sending messages in batches](https://open.larksuite.com/document/ukTMukTMukTM/ucDO1EjL3gTNx4yN4UTM) API currently.

**Example**
```json
{
    "receive_id": "oc_xxx",
    "content": "{\"text\":\"[Lark Open Platform](https://open.larksuite.com)\"}",
    "msg_type": "text"
}
```

### Rich text post
- A rich-text message supports using the text, @mention, image, hyperlink and other elements at the same time.
- A rich-text message can be divided into multiple paragraphs (consisting of multiple [] sections), each of which can be composed of multiple elements. Each element consists of "tag" and corresponding field description. The main image element must be a separate paragraph.
```json 
{
	"zh_cn": {
		"title": "Title",
		"content": [
			[	
				{
					"tag": "text",
					"text": "The first line:",
					"style": ["bold", "underline"]
				},
				{
					"tag": "a",
					"href": "https://open.larksuite.com",
					"text": "Open Platform",
					"style": ["bold", "italic"]
				},
				{
					"tag": "at",
					"user_id": "ou_1avnmsbv3k45jnk34j5",
					"style": ["lineThrough"]
				}
			],
			[{
				"tag": "img",
				"image_key": "img_7ea74629-9191-4176-998c-2e603c9c5e8g"
			}],
			[
				{
					"tag": "text",
					"text": "The second line:",
					"style": ["bold", "underline"]
				},
				{
					"tag": "text",
					"text": "Text test"
				}
			],
			[{
				"tag": "img",
				"image_key": "img_7ea74629-9191-4176-998c-2e603c9c5e8g"
			}],
			[{
				"tag": "media",
				"file_key": "file_v2_0dcdd7d9-fib0-4432-a519-41d25aca542j",
				"image_key": "img_7ea74629-9191-4176-998c-2e603c9c5e8g"
			}],
          	[{
				"tag": "emotion",
				"emoji_type": "SMILE"
			}],
			[{
				"tag": "hr"
			}],
			[{
				"tag": "code_block",
				"language": "GO",
				"text": "func main() int64 {\n    return 0\n}"
			}],
			[{
				"tag": "md",
				"text": "**mention user:**<at user_id=\"ou_xxxxxx\">Tom</at>\n**href:**[Open Platform](https://open.larksuite.com)\n**code block:**\n```GO\nfunc main() int64 {\n    return 0\n}\n```\n**text styles:** **bold**, *italic*, ***bold and italic***, ~underline~,~~lineThrough~~\n> quote content\n\n1. item1\n    1. item1.1\n    2. item2.2\n2. item2\n --- \n- item1\n    - item1.1\n    - item2.2\n- item2"
			}],
		]
	},
	"en_us": {
		...
	}
}
``` 

**Rich Text Parameter Description**

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| ∟zh_cn, en_us | object | Yes |`zh_cn` and `en_us` are the Chinese and English configurations of rich text respectively. If i18N messages are not required, you only need to configure one language, but at least one language configuration must be included. | none | en_us
| ∟title | string | No | The title of the rich text message. | none | "title" |
| ∟content | [][]node | Yes | Rich text message content, consisting of multiple paragraphs; each paragraph is a node list, the supported node labels and corresponding parameters are detailed in **Tags and Parameters Supported by Rich Text** section of this article.| [] | [[{"tag": "text","text": "text content"}]] |

**Tags and Parameters Supported by Rich Text**warning
This capability **does not support** custom bots and [sending messages in batches](https://open.larksuite.com/document/ukTMukTMukTM/ucDO1EjL3gTNx4yN4UTM) API currently.

**text** 

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| text | string | Yes | Text content. | none | Test content |
| un\_escape | bool | No | Whether to decode with unescape. The default value is false, and this field is optional. | false | false |
| style | []string | No | Used to configure the bold, underline, strikeline and italic styles of the text content. The optional values are `bold`, `underline`, `lineThrough` and `italic`, and the non-optional values will be ignored. | [] | ["bold", "underline"] |

**a** 

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| text | string | Yes | Text content. | none | Hyperlink |
| href | string | Yes | Default link address. Please ensure the legitimacy of the href, otherwise the message will fail to be sent. | none | https://open.larksuite.com |
| style | []string | No | Used to configure the bold, underline, strikeline and italic styles of the text content. The optional values are `bold`, `underline`, `lineThrough` and `italic`, and the non-optional values will be ignored. | [] | ["bold", "underline"] |

**at** 

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| user\_id | string | Yes | open_id, union_id or user_id of the user to @mention. Please refer to [How to get User ID, Open ID and UnionID?](https://open.larksuite.com/document/home/user-identity-introduction/open-id) for ID acquisition. <br> **Note**: When you @mention a single user, open_id must be a valid value, which is "all" for @mentioning all users. |none  | ou\_18eac85d35a26f989317ad4f02e8bbbb |
| style | []string | No | Used to configure the bold, underline, strikeline and italic styles of the text content. The optional values are `bold`, `underline`, `lineThrough` and `italic`, and the non-optional values will be ignored. | [] | ["bold", "underline"] |

**img** 

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| image\_key | string | Yes | Unique identifier of the image. You can obtain image_key through the [Upload images](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/image/create) API. | none | d640eeea-4d2f-4cb3-88d8-c964fab53987 |

**media** 

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| file\_key | string | Yes | Unique identifier of the media file. You can obtain file_key through the [Upload files](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/file/create) API. | none | file_v2_0dcdd7d9-fib0-4432-a519-41d25aca542j |
| image\_key | string | No | Unique identifier of the media cover image. You can obtain image_key through the [Upload images](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/image/create) API. |none  | img_7ea74629-9191-4176-998c-2e603c9c5e8g |

**emotion** 

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| emoji_type | string | Yes | Emoji type. For some optional values, please refer to [Emoji copy](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message-reaction/emojis-introduce). | none | SMILE |

#### code_block
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| language | string | No | Code block language, do not fill in text type. Optional values are: PYTHON, C, CPP, GO, JAVA, KOTLIN, SWIFT, PHP, RUBY, RUST, JAVASCRIPT, TYPESCRIPT, BASH, SHELL, SQL, JSON, XML, YAML , HTML, THRIFT, etc., not case sensitive | none | GO |
| text | string | Yes | The content of the code block | none | func main() int64 {\n    return 0\n} |

#### hr

Rich text supports the hr tag, indicating a horizontal rule, or divider. It does not accept any other parameters.

#### mdwarning
**Notice**:
1. The `md` tag will occupy one or more paragraphs and cannot be in the same line with other tags.
2. The `md` tag only supports sending. When obtaining the message content, this tag will not be included and will be converted into other tags based on the content in `md`.
3. References, ordered and unordered lists will degenerate into text tags for output.

Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| text | string | Yes | markdown content, the supported syntax is shown in the table below | none | 1. item1\n2. item2 |

| Syntax |  Example | Instructions for use |
| --- | --- | --- | --- |
| @user | <at user_id="ou_xxxxx">Tom</at> | Refer to the **Instructions on Text-message @mentioning Usage** section |
| Hyperlink |\[Lark Open Platform](https://open.larksuite.com) | For usage instructions, please refer to the "Instructions on Hyperlink Usage" section of this article. If the link is illegal, only the text part will be sent.  |
| Ordered list | 1. item1\n2. item2  |  1. In each item, there must be a space after "."; <br> 2. Each item must be on a separate line; <br>3. When used at multiple levels, each level should be indented by 4 spaces, and the numbering should start from 1. ;<br> 4. Can be mixed with unordered lists;  |
| Unordered list | - item1\n- item2 |1. In each item, there must be a space after "-"; <br> 2. Each item must be on a separate line; <br>3. When used at multiple levels, each additional level must be indented by 4 spaces; <br> > 4. Can be mixed with ordered lists. Each level must be indented by 4 spaces and then numbered again starting with 1.; |
| Code block | \```GO\nfunc main(){\n    return\n}\n\``` | Use \``` before and after the code block. The first \``` is followed by the language type. It supports PYTHON, C, CPP, GO, JAVA, KOTLIN, SWIFT, PHP, RUBY, RUST, JAVASCRIPT, TYPESCRIPT, BASH, SHELL, and SQL. , JSON, XML, YAML, HTML, THRIFT and other languages (not case sensitive) | 
| Quote | > quote content | There must be a space after ">"
|Divider| \n --- \n|There needs to be a newline character before and after
|Bold| `**bold text**`| 1. There can be no space between ** and the text; <br> 2. The text part does not support parsing other syntaxes. For example, if the text part is a hyperlink, it will not be parsed. <br> 3. Can be used in combination with italics, such as `***bold + italics***`.
|Italic| `*italic text*`| 1. There cannot be a space between * and the text; <br> 2. The text part does not support parsing other syntaxes. For example, if the text part is a hyperlink, it will not be parsed. <br> 3. Can be used in combination with italics, such as `***bold + italics***`.
|Underline| `~underline~`| 1. There cannot be a space between ~ and the text; <br> 2. The text part does not support parsing other syntaxes. For example, if the text part is a hyperlink, it will not be parsed. <br> 3. **Not supported** can be used with bold, italics, and linethrough.
|Linethrough | `~~linethrough~~`| 1. There can be no space between ~~ and the text; <br>2. The text part does not support parsing other syntaxes. For example, if the text part is a hyperlink, it will not be parsed. <br> 3. **Not supported** is used with bold, italics, and underline, such as `~~~test~~~`, `**~~bold strikethrough~~**`.

**Message-sending Request Body Example**

```json 
{
	"receive_id": "oc_820faa21d7ed275b53d1727a0feaa917",
	"content": "{\"zh_cn\":{\"title\":\"Title\",\"content\":[[{\"tag\":\"text\",\"text\":\"The first line::\"},{\"tag\":\"a\",\"href\":\"http://www.larksuite.com\",\"text\":\"Hyperlink\"},{\"tag\":\"at\",\"user_id\":\"ou_1avnmsbv3k45jnk34j5\",\"user_name\":\"tom\"}],[{\"tag\":\"img\",\"image_key\":\"img_7ea74629-9191-4176-998c-2e603c9c5e8g\"}],[{\"tag\":\"text\",\"text\":\"The second line:\"},{\"tag\":\"text\",\"text\":\"Text test\"}],[{\"tag\":\"img\",\"image_key\":\"img_7ea74629-9191-4176-998c-2e603c9c5e8g\"}]]}}",
	"msg_type": "post"
}
```

### Image
```json 
{
    "image_key": "img_7ea74629-9191-4176-998c-2e603c9c5e8g"
}
``` 

**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| image\_key | string | Yes | Unique identifier of the media cover image. You can obtain image_key through the [Upload images](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/image/create) API. |none  | img_7ea74629-9191-4176-998c-2e603c9c5e8g |

**Message-sending Request Body Example**

```json 
{
	"receive_id": "oc_xxx",
	"content": "{\"image_key\": \"img_v2_xxx\"}",
	"msg_type": "image"
} 
```

### Interactive
Lark open platform defines structured components and styles for message cards. You can define beautifully styled and interactive card content through JSON description. For card structure description, please refer to [card structure](https://open.larksuite.com/document/ukTMukTMukTM/ugTNwUjL4UDM14CO1ATN).

Lark open platform provides a visual [message card builder](https://open.larksuite.com/tool/cardbuilder), in which you can build, browse, and save message cards, making it easier for you to flexibly build message cards.
Note:<br>
- If you are using an older version of the ==Send message cards== API (`/open-apis/message/v4/send/`), replace the `content` parameter with `card` in the request body. In the [Send a message](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create) API, the content parameter is always `content` in the request body.
- The `update_multi` field of the message card (whether the card is a public card or not) is set in the `config` structure of the card content. For details, refer to [card structure](https://open.larksuite.com/document/ukTMukTMukTM/ugTNwUjL4UDM14CO1ATN).

**Message-sending Request Body Example**
- Send with card JSON
```json 
  {
      "receive_id": "oc_820faa21d7ed275b53d1727a0feaa917",
      "content": "{\"config\":{\"wide_screen_mode\":true},\"elements\":[{\"alt\":{\"content\":\"\",\"tag\":\"plain_text\"},\"img_key\":\"img_7ea74629-9191-4176-998c-2e603c9c5e8g\",\"tag\":\"img\"},{\"tag\":\"div\",\"text\":{\"content\":\"Have you ever had a spiritual resonance because of a book and started to understand life?\\ nWhich favorite books that you would strongly recommend to others?\\ n\\nJoin **4/23 Lark Reading Festival**, share your **favorite books** and **reading notes** to **win a reading gift worth one thousand CNY**!\\ n\\n Complete the questionnaire and show us your favorite books\\n Want to know what books others have recommended? View them now by [joining the group](https://open.larksuite.com/)\\nUse the [reading note template](https://open.larksuite.com/) (Open it in the desktop app) to record your experience\\nSpecial guests will join us from April 12\",\"tag\":\"lark_md\"}},{\"actions\":[{\"tag\":\"button\",\"text\":{\"content\":\"Recommend a good book now\",\"tag\":\"plain_text\"},\"type\":\"primary\",\"url\":\"https://open.larksuite.com/\"},{\"tag\":\"button\",\"text\":{\"content\":\"View the activity guide\",\"tag\":\"plain_text\"},\"type\":\"default\",\"url\":\"https://open.larksuite.com/\"}],\"tag\":\"action\"}],\"header\":{\"template\":\"turquoise\",\"title\":{\"content\":\"Show us your favorite books and win reading gifts\",\"tag\":\"plain_text\"}}}",
      "msg_type": "interactive"
  } 
``` 

- send with card `template_id`

```JSON
  {
      "receive_id": "ou_7d8a6exxxxccs",
      "msg_type": "interactive",
      "content": "{\"type\": \"template\", \"data\": { \"template_id\": \"ctp_xxxxxxxxxxxx\", \"template_variable\": {\"article_title\": \"这是文章标题内容\"} } }"
  }
```

**Parameter Description**
Field |Type|Required| Description|Example|
| --- | --- | --- | --- | --- |
| type | string | Yes | Fixed value：`template`.  |template
| data | object | Yes | Card template data. |  {}   |  
| ∟template_id | string |  Yes | The card template ID, which can be obtained by copying the card ID in the message card building tool. | ctp_xxxxxxx 
| ∟template_variable | object | No | The value of the variable data in the card is in the form of {key:value}, where key represents the name of the variable. The value represents the value of the variable. | {"key":"value"}

### Share_chat
```json 
{
    "chat_id": "oc_0dd200d32fda15216d2c2ef1ddb32f76"
}
``` 

**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| chat_id | string | Yes | Group ID. For how to obtain chat_id, please refer to [Group ID description](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/chat-id-description). |none  | oc_0dd200d32fda15216d2c2ef1ddb32f76 |

**Message-sending Request Body Example**

```json 
 {
	"receive_id": "oc_xxx",
	"content": "{\"chat_id\":\"oc_xxx\"}",
	"msg_type": "share_chat"
}
``` 
- The bot must be in the group chat where the group card is located.

### Share_user
- `user_id` only supports [Open ID](https://open.larksuite.com/document/home/user-identity-introduction/open-id), and the robot must be visible to the user.
- Currently does not support sharing the user card of the robot.

```json 
{
    "user_id": "ou_0dd200d32fda15216d2c2ef1ddb32f76"
} 
``` 

**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| user_id | string | Yes | User's [Open ID](https://open.larksuite.com/document/home/user-identity-introduction/open-id). For how to get it, please refer to [Learn more: How to obtain Open ID](https://open.larksuite.com/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid).|none  | ou_0dd200d32fda15216d2c2ef1ddb32f76 |

**Message-sending Request Body Example**

```json 
{
	"receive_id": "oc_820faa21d7ed275b53d1727a0feaa917",
	"content": "{\"user_id\":\"ou_xxx\"}",
	"msg_type": "share_user"
} 
```

### Audio
```json 
{
    "file_key": "75235e0c-4f92-430a-a99b-8446610223cg"     // File key
}
``` 

**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| file_key | string | Yes | Audio file Key, the file_key of the audio file can be obtained through the [Upload files](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/file/create) API. |none  | 75235e0c-4f92-430a-a99b-8446610223cg |

**Message-sending Request Body Example**

```json 
{
	"receive_id": "oc_xxx",
	"content": "{\"file_key\":\"file_v2_xxx\"}",
	"msg_type": "audio"
} 
```

### Media
```json 
{
    "file_key": "75235e0c-4f92-430a-a99b-8446610223cg", // File key
    "image_key": "img_xxxxxx"  // Key of the video cover image
}
``` 

**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| file_key | string | Yes | video file Key, the file_key of the video file can be obtained through the [Upload files](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/file/create) API. |none  | 75235e0c-4f92-430a-a99b-8446610223cg |
| image_key | string | No | The key of the video cover image, the image_key of the image can be obtained through the [Upload images](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/image/create) API. |none  | img_xxxxxx |

**Message-sending Request Body Example**

```json 
{
    "receive_id": "oc_xxx",
    "content": "{\"file_key\":\"file_v2_xxx\",\"image_key\":\"img_v2_xxx\"}",
    "msg_type": "media"
} 
``` 

### File
```json 
{
    "file_key": "75235e0c-4f92-430a-a99b-8446610223cg"
}
``` 
**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| file_key | string | Yes | File Key, the file_key can be obtained through the [Upload files](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/file/create) API. |none  | 75235e0c-4f92-430a-a99b-8446610223cg |

**Message-sending Request Body Example**
```json 
{
	"receive_id": "oc_820faa21d7ed275b53d1727a0feaa917",
	"content": "{\"file_key\":\"file_v2_xxx\"}",
	"msg_type": "file"
} 
```

### Sticker
Currently, only emojis received by the bot can be sent. You can obtain the file_key of the emoji package through the API [Receive message events](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/events/receive).
```json 
{
    "file_key": "75235e0c-4f92-430a-a99b-8446610223cg"
}
``` 

**Parameter Description**
Field |Type|Required| Description|Default value|Example|
| --- | --- | --- | --- | --- | --- |
| file_key | string | Yes | Sticker file key, currently only supports sending stickers received by the bot. You can obtain the file_key of the emoji package through the API [Receive message events](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/events/receive).|none  | 75235e0c-4f92-430a-a99b-8446610223cg |

**Message-sending Request Body Example**

```json 
{
	"receive_id": "oc_xxx",
	"content": "{\"file_key\":\"file_v2_xxx\"}",
	"msg_type": "sticker"
} 
``` 
