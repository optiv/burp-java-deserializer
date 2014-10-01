package burp;

import com.accuvantlabs.burp.InspectTab;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private static final String NAME = "Java Object Deserializer";
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName(NAME);

		// register ourselves as a message editor tab factory
		callbacks.registerMessageEditorTabFactory(this);
	}

	@Override
	public IMessageEditorTab createNewInstance(
			IMessageEditorController controller, boolean editable) {
		// TODO Auto-generated method stub
		return new InspectTab(controller, editable, callbacks);
	}

}
