package com.accuvantlabs.burp;

import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectStreamConstants;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.unsynchronized.ValidityException;
import org.unsynchronized.classdesc;
import org.unsynchronized.classdesctype;
import org.unsynchronized.content;
import org.unsynchronized.field;
import org.unsynchronized.fieldtype;
import org.unsynchronized.instance;
import org.unsynchronized.jdeserialize;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.ITextEditor;

public class InspectTab implements IMessageEditorTab {

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private boolean editable;
	private ITextEditor txtInput;
	private byte[] currentMessage;
	
	private byte[] serializeMagic = new byte[]{-84, -19};

	public InspectTab(IMessageEditorController controller, boolean editable,
			IBurpExtenderCallbacks callbacks) {
		this.editable = editable;

		// create an instance of Burp's text editor, to display our deserialized
		// data
		txtInput = callbacks.createTextEditor();
		txtInput.setEditable(editable);

		this.callbacks = callbacks;
		this.helpers = this.callbacks.getHelpers();
	}

	//
	// implement IMessageEditorTab
	//

	@Override
	public String getTabCaption() {
		return "Java Object";
	}

	@Override
	public Component getUiComponent() {
		return txtInput.getComponent();
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		// enable this tab for requests containing a data parameter
		
		return helpers.indexOf(content, serializeMagic, false, 0, content.length) > -1;
	}
	
	private byte[] extractBody(byte[] content, boolean isRequest)
	{
		int offset = -1;
		if(isRequest)
			offset = helpers.analyzeRequest(content).getBodyOffset();
		else 
			offset = helpers.analyzeResponse(content).getBodyOffset();
		if(offset == -1)
			return new byte[]{};
		return Arrays.copyOfRange(content, offset, content.length);
	}
	
	private byte[] extractJavaClass(byte[] data) {
		int magicPos = helpers.indexOf(data, serializeMagic, false, 0, data.length);
		return Arrays.copyOfRange(data, magicPos, data.length);
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		if (content == null) {
			// clear our display
			txtInput.setText(null);
			txtInput.setEditable(false);
		} else {

			byte[] body = extractBody(content, isRequest);
			
			ByteArrayInputStream bais =  new ByteArrayInputStream(extractJavaClass(body));
			
			jdeserialize jd = new jdeserialize("");
			try {
				jd.run(bais, true, 0);
				
				StringBuffer out = new StringBuffer();
				for(content c : jd.getContent()) {
					// output class name
					out.append(c.toString() + "\n");
//                    if(c instanceof blockdata) {
//                        blockdata bd = (blockdata)c;
//                        out.append(bd.buf.length); //????
//                        out.append(bd.buf); //?????
//                    }
				}
				List<Map<Integer, content>> handlesList = jd.getHandleMaps();
				
				ArrayList<instance> classInstances = new ArrayList<instance>();
				for(Map<Integer, content> handles : handlesList) {
					for(content c: handles.values()) {
		                if(c instanceof classdesc) {
		                    classdesc cl = (classdesc)c;

		                    // Member classes will be displayed as part of their enclosing
		                    // classes.
		                    if(cl.isStaticMemberClass() || cl.isInnerClass()) {
		                        continue;
		                    }

		                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
		                    PrintStream ps = new PrintStream(baos);
		                    dump_ClassDesc(0, cl, ps, true);
		                    out.append(baos.toString());
		                    
		                    out.append("\n");
		                }
		                if(c instanceof instance) {
		                	instance ci = (instance)c;
		                	classInstances.add(ci);
		                	ByteArrayOutputStream baos = new ByteArrayOutputStream();
		                    PrintStream ps = new PrintStream(baos);
		                    jdeserialize.dump_Instance(0, ci, ps);
		                    out.append(baos.toString());
		                    out.append("\n");
		                }
		            }
				}
				// deserialize the parameter value
				txtInput.setText(out.toString().getBytes());
				txtInput.setEditable(editable);
			} catch (IOException e) {
				txtInput.setText(e.getMessage().getBytes());
				e.printStackTrace();
			}
			
			
            
		
		}

		// remember the displayed content
		currentMessage = content;
	}
	
	public static void dump_ClassDesc(int indentlevel, classdesc cd, PrintStream ps, boolean fixname) throws IOException {
        String classname = cd.name;
        if(fixname) {
            classname = jdeserialize.fixClassName(classname);
        }
        if(cd.annotations != null && cd.annotations.size() > 0) {
            ps.println(jdeserialize.indent(indentlevel) + "// annotations: ");
            for(content c: cd.annotations) {
                ps.print(jdeserialize.indent(indentlevel) + "// " + jdeserialize.indent(1));
                ps.println(c.toString());
            }
        }
        // Class
        if(cd.classtype == classdesctype.NORMALCLASS) {
        	// Enumeration
            if((cd.descflags & ObjectStreamConstants.SC_ENUM) != 0) {
                ps.print(jdeserialize.indent(indentlevel) + "enum " + classname + " {");
                boolean shouldindent = true;
                int len = jdeserialize.indent(indentlevel+1).length();
                for(String econst: cd.enumconstants) {
                    if(shouldindent) {
                        ps.println("");
                        ps.print(jdeserialize.indent(indentlevel+1));
                        shouldindent = false;
                    }
                    len += econst.length();
                    ps.print(econst + ", ");
                    if(len >= jdeserialize.CODEWIDTH) {
                        len = jdeserialize.indent(indentlevel+1).length();
                        shouldindent = true;
                    }
                }
                ps.println("");
                ps.println(jdeserialize.indent(indentlevel) + "}");
                return;
            } 
            ps.print(jdeserialize.indent(indentlevel));
            if(cd.isStaticMemberClass()) {
                ps.print("static ");
            }
            ps.print("class " + (classname.charAt(0) == '[' ? jdeserialize.resolveJavaType(fieldtype.ARRAY, cd.name, false, fixname) : classname));
            if(cd.superclass != null) {
                ps.print(" extends " + cd.superclass.name);
            }
            
            // Implements either Externalizable or Serializable
            ps.print(" implements ");
            if((cd.descflags & ObjectStreamConstants.SC_EXTERNALIZABLE) != 0) {
                ps.print("java.io.Externalizable");
            } else {
                ps.print("java.io.Serializable");
            }
            
            // Implements OTHER interfaces
            if(cd.interfaces != null) {
                for(String intf: cd.interfaces) {
                    ps.print(", " + intf);
                }
            }
            ps.println(" {");
            // End class def, continue to field members
            
            for(field f: cd.fields) {
                if(f.isInnerClassReference()) {
                    continue;
                }
                ps.print(jdeserialize.indent(indentlevel+1) + f.getJavaType());
                ps.println(" " + f.name + ";");
                
            }
            
            // Recursively dump inner classes
            for(classdesc icd: cd.innerclasses) {
                dump_ClassDesc(indentlevel+1, icd, ps, fixname);
            }
            ps.println(jdeserialize.indent(indentlevel)+"}");
            
        } else if(cd.classtype == classdesctype.PROXYCLASS) {
            ps.print(jdeserialize.indent(indentlevel) + "// proxy class " + jdeserialize.hex(cd.handle));
            if(cd.superclass != null) {
                ps.print(" extends " + cd.superclass.name);
            }
            ps.println(" implements ");
            for(String intf: cd.interfaces) {
                ps.println(jdeserialize.indent(indentlevel) + "//    " + intf + ", ");
            }
            if((cd.descflags & ObjectStreamConstants.SC_EXTERNALIZABLE) != 0) {
                ps.println(jdeserialize.indent(indentlevel) + "//    java.io.Externalizable");
            } else {
                ps.println(jdeserialize.indent(indentlevel) + "//    java.io.Serializable");
            }
        } else {
            throw new ValidityException("encountered invalid classdesc type!");
        }
    }

	@Override
	public byte[] getMessage() {
		// determine whether the user modified the deserialized data
//		if (txtInput.isTextModified()) {
//			// reserialize the data
//			byte[] text = txtInput.getText();
//			String input = helpers.urlEncode(helpers.base64Encode(text));
//
//			// update the request with the new parameter value
//			return helpers.updateParameter(currentMessage, helpers
//					.buildParameter("data", input, IParameter.PARAM_BODY));
//		} else
			return currentMessage;
	}

	@Override
	public boolean isModified() {
		return txtInput.isTextModified();
	}

	@Override
	public byte[] getSelectedData() {
		return txtInput.getSelectedText();
	}

}
